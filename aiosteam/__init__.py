import os
import re
import json
import time
import gzip
import struct
import binascii

from hashlib import sha1

from io import BytesIO
from socket import socket, inet_aton
from urllib.parse import urlencode

import asyncio
from asyncio import wait_for

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5

import aiohttp

from .enums import *
from .enums.emsg import EMsg

from . import msg
from . import crypto


__version__ = "0.0.1"


class TCPConnection(object):
    def __init__(self, loop=None):
        self._packstr = "<I4s"
        self._magic = b"VT01"
        self._socket = socket()
        self._socket.setblocking(False)
        self._loop = loop or asyncio.get_event_loop()


    def sockname(self):
        return self._socket.getsockname()


    async def connect(self, host, port):
        try:
            await wait_for(self._loop.sock_connect(self._socket, (host, port)), timeout=5)
        except Exception as e:
            return False
        return True


    def close(self):
        self._socket.close()


    async def send(self, msg):
        packet = struct.pack(self._packstr, len(msg), self._magic) + msg
        return (await self._loop.sock_sendall(self._socket, packet))


    async def recv(self):
        header_length = 8
        header = b""
        while header_length > 0:
            part = await self._loop.sock_recv(self._socket, header_length)
            if not part: return part
            header_length -= len(part)
            header += part

        body_length, magic = struct.unpack_from("<I4s", header)
        if magic != self._magic: raise type("InvalidMagic", (Exception,), {})()

        buffer = BytesIO()
        while body_length > 0:
            body = await self._loop.sock_recv(self._socket, body_length)
            body_length -= len(body)
            buffer.write(body)
        return bytes(buffer.getbuffer())



class SteamClient(object):
    def __init__(self, username, password, login_key="", proto="tcp", loop=None):
        self.connected = False
        self.username = username
        self.password = password
        self.api_key = None
        self.logged_on = False
        self.login_key = login_key
        self.steamid = -1
        self.sessionid = -1
        self.cell_id = -1
        self.vanity_url = None
        self.webapi_authenticate_user_nonce = None
        self.sentry = None
        self.sha_sentryfile = None

        self._channel_encrypt_key = None
        self._channel_encrypt_hmac= None
        self._loop = loop or asyncio.get_event_loop()
        self._session = None
        # self._loop.set_debug(enabled=True)
        self._proto = proto
        self._connection = None
        self._heartbeat = None

        self.__listeners__ = {}
        self.__waiting__ = {}
        self.__current_server__ = None
        self.__bad_servers__ = set()


    def on(event):
        def wrap(func):
            async def _wrap(msg, resp):
                r = func(msg, resp)
                if asyncio.iscoroutine(r):
                    return (await r)
                return r
            self.__listeners__[event].setdefault(set())
            self.__listeners__[event].add(_wrap)
            return _wrap
        return wrap


    async def emit(self, event, resp=None):
        if type(event) == int: event = EMsg(event)
        if type(event) == EMsg: event = event.name
        for cb in [getattr(self, 'on'+event, None), getattr(self, "onEMsg"+event, None)] + \
                  list(self.__listeners__.get(event, [])):
            if not cb: continue
            r = cb(resp)
            if asyncio.iscoroutine(r): r = await r

        listeners = self.__waiting__.get(event, set())

        while listeners:
            w = listeners.pop()
            w.set_result(resp or event)


    async def ready(self, event, packet=None):
        if type(event) == EMsg: event = event.name
        self.__waiting__.setdefault(event, set())
        future = asyncio.Future(loop=self._loop)
        self.__waiting__[event].add(future)
        if packet:
            await self.send(packet)
        return (await future)


    async def recv(self):
        s = await self._connection.recv()
        if not s: return s
        if self._channel_encrypt_key:
            m ="hmac" if self._channel_encrypt_hmac else "base"
            s = crypto.decrypt(s, self._channel_encrypt_key, self._channel_encrypt_hmac, m)
        r = msg.loads(s)
        return r


    async def send(self, packet):
        if type(packet) == dict:
            packet = msg.Message(packet)
            if self.steamid != -1: packet.header.steamid = self.steamid
            if self.sessionid != -1: packet.header.client_sessionid = self.sessionid
        p = msg.dumps(packet)
        if self._channel_encrypt_key:
            m ="hmac" if self._channel_encrypt_hmac else "base"
            p = crypto.encrypt(p, self._channel_encrypt_key, self._channel_encrypt_hmac, m)
        return (await self._connection.send(p))


    async def connect(self, retry=0):
        async def __reader__():
            while self.connected:
                try:
                    r = await self.recv()
                    if not r: (await asyncio.sleep(0.1)); continue
                    self._loop.create_task(self.emit(r.msg.name, r))
                except Exception as e:
                    await asyncio.sleep(0.2)
        async def __switch__():
            await self.ready(event=EMsg.ChannelEncryptRequest)

        if self.connected: return True
        celid = 3
        self._connection = TCPConnection(loop=self._loop)
        while retry >= 0:
            servers = await self.servers(celid)
            for server in servers:
                if server in self.__bad_servers__: continue
                host, port = server.split(":")
                if (await self._connection.connect(host, int(port))):
                    self.connected = True
                    self.__current_server__ = server
                    self._loop.create_task(__reader__())
                    await __switch__()
                    return True
                self.__bad_servers__.add(server)
            celid += 1
            retry -= 1
        return False


    async def disconnect(self, exc=None):
        if exc:
            self.__bad_servers__.add(self.__current_server__)
        self.connected = False
        self._connection.close()
        await self.emit("disconnected", exc)


    async def login(self, auth_type="2fa", auth_code=""):
        if not self.connected:
            await self.connect()
        if not self.connected:
            raise type("ConnectionError", (Exception,), {})("Fail to connect to cmserver.")
        packet = {
            "msg": EMsg.ClientLogon,
            "header": {
                # SteamID(type='Individual', universe='Public')
                "steamid": 76561197960265728,
                },
            "body": {
                "protocol_version": 65579,
                "client_package_version": 1771,
                "client_os_type": EOSType.Win10,
                "should_remember_password": True,
                "supports_rate_limit_response": True,
                "eresult_sentryfile": EResult.FileNotFound,
                }
            }
        packet["body"]["obfustucated_private_ip"] = struct.unpack(">L", inet_aton(self._connection.sockname()[0]))[0] ^ msg.obfuscation_mask
        packet["body"]["account_name"] = self.username

        if self.login_key:
            packet["body"]["login_key"] = self.login_key
        else:
            packet["body"]["password"] = self.password

        if self.sentry:
            packet["body"]["eresult_sentryfile"] = EResult.OK
            packet["body"]["sha_sentryfile"] = self.sha_sentryfile

        if auth_code:
            if auth_type == "2fa":
                packet["body"]["two_factor_code"] = auth_code
            elif auth_type == "email":
                packet["body"]["auth_code"] = auth_code

        r = await self.ready(event=EMsg.ClientLogOnResponse, packet=packet)
        return r


    async def logout(self):
        packet = {
            "msg": EMsg.ClientLogOff
            }
        self._heartbeat.cancel()
        await self.send(packet)
        self.logged_on = False
        self.webapi_authenticate_user_nonce = None
        # self.login_key = None
        self.steamid = -1
        self.sessionid = -1
        self.sentry = None
        self.sha_sentryfile = None


    async def servers(self, cellid=0, maxcount=4):
        url = "http://api.steampowered.com/ISteamDirectory/GetCMList/v0001/?cellid=%d&maxcount=%d" % (cellid, maxcount)
        r = await aiohttp.get(url)
        j = await r.json()
        return j.get("response", {}).get("serverlist", [])


    async def games_played(self, appids):
        self.current_games_played = appids = list(map(int, appids))
        packet = {
            "msg": EMsg.ClientGamesPlayed,
            "body": {
                "games_played": [{"game_id": id} for id in appids]
                }
            }
        await self.send(packet)


    async def session(self, refresh=False):
        if self._session and not refresh: return self._session
        key, encrypted_key = crypto.session_key()
        auth_packet = {
            "steamid": self.steamid,
            "sessionkey": encrypted_key,
            "encrypted_loginkey": crypto.encrypt(self.webapi_authenticate_user_nonce, key)
            }
        steamuserauth_uri = "https://api.steampowered.com/ISteamUserAuth/AuthenticateUser/v0001/"

        # ATTENTION: Need encode data manually and set header Content-Type to `application/x-www-form-urlencoded`.
        data = urlencode(auth_packet)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
            }
        auth_resp = await aiohttp.post(steamuserauth_uri, data=data, headers=headers)
        auth_json = await auth_resp.json()

        sessionid = binascii.hexlify(sha1(os.urandom(32)).digest())[:32].decode('ascii')
        cookies = {
            "Steam_Language": "english",
            "birthtime": "-3333",
            "sessionid": sessionid,
            "steamLogin": auth_json['authenticateuser']['token'],
            "steamLoginSecure": auth_json['authenticateuser']['tokensecure'],
            }

        session = aiohttp.ClientSession(cookies=cookies, loop=self._loop)

        async def api_key(self):
            url = "http://steamcommunity.com/dev/apikey"
            r = await self.get(url)
            t = await r.text()
            return re.search("[A-Z0-9]{32}", t)[0]

        if not self.api_key:
            self.api_key = await api_key(session)
        if not self.api_key: session.close(); return None
        self._session = session
        return session


    async def games(self):
        if not self.api_key: await self.session()
        if not self.api_key: return {}
        url = "https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/?key={}&steamid={}&include_appinfo=1"
        url = url.format(self.api_key, self.steamid)
        try:
            r = await aiohttp.get(url)
            t = await r.json()
        except Exception as e:
            return {}
        return {
            i['appid'] : {
                'name': i['name'],
                'played_time': i['playtime_forever']
            } for i in t.get('response', {}).get('games', [])
        }


    async def cards_remain(self, appid):
        url = "http://steamcommunity.com/id/luxrck/gamecards/{}".format(appid)
        s = await self.session()
        if not s: return 0
        r = await s.get(url)
        t = await r.text()
        doc = re.findall("(?:progress_info_bold)(.*)(?:span)", t)[0]
        cards = re.findall("\d+", doc)
        return (0 if not cards else int(cards[0]))


    async def onEMsgMulti(self, resp):
        if resp.body.size_unzipped:
            data = gzip.decompress(resp.body.message_body)
            if len(data) != resp.body.size_unzipped:
                e = type("UnzipError", (Exception,), {})("Uncompressed data length mismatch.")
                return (await self.disconnect(exc=e))
        else:
            data = resp.body.message_body

        while len(data) > 0:
            size, = struct.unpack_from("<I", data)
            r = msg.loads(data[4:4+size])
            await self.emit(r.msg, r)
            data = data[4+size:]


    async def onEMsgClientNewLoginKey(self, req):
        resp = {
            "msg": EMsg.ClientNewLoginKeyAccepted,
            "body": {
                "unique_id": req.body.unique_id
                }
            }
        if self.logged_on:
            await self.send(resp)
            self.login_key = req.body.login_key
            open("user.login_key", "w").write(self.login_key)


    async def onEMsgClientLogOnResponse(self, resp):
        result = resp.body.eresult
        if result == EResult.OK:
            self.logged_on = True
            self.steamid = resp.header.steamid
            self.sessionid = resp.header.client_sessionid
            self.vanity_url = resp.body.vanity_url
            self.cell_id = resp.body.cell_id
            self.webapi_authenticate_user_nonce = resp.body.webapi_authenticate_user_nonce.encode("ascii")

            interval = resp.body.out_of_game_heartbeat_seconds
            async def __heartbeat__(interval):
                packet = {"msg": EMsg.ClientHeartBeat}
                while self.logged_on:
                    await asyncio.sleep(interval)
                    try:
                        await self.send(packet)
                    except:
                        pass
            self._heartbeat = self._loop.create_task(__heartbeat__(interval))

            # set client persona state
            persona = {
                "msg": EMsg.ClientChangeStatus,
                "body": {
                    "persona_state": EPersonaState.Online,
                    }
                }
            await self.send(persona)
            await self.emit("logged_on")
        elif result in (EResult.TryAnotherCM,
                        EResult.ServiceUnavailable):
            await self.disconnect()
        return resp


    async def onEMsgClientUpdateMachineAuth(self, req):
        self.sentry = req.body.bytes
        self.sha_sentryfile = sha1(self.sentry).digest()
        resp = {
            "msg": EMsg.ClientUpdateMachineAuthResponse,
            "header": {
                "jobid_target": req.header.jobid_source,
                },
            "body": {
                "filename": req.body.filename,
                "eresult": EResult.OK,
                "sha_file": self.sha_sentryfile,
                "getlasterror": 0,
                "offset": req.body.offset,
                "cubwrote": req.body.cubtowrite,
                }
            }
        open("user.sentry", "wb").write(self.sentry)
        open("user.sentry.sha_sentryfile", "wb").write(self.sha_sentryfile)
        await self.send(resp)


    async def onEMsgChannelEncryptRequest(self, req):
        try:
            if req.body.version != 1:
                raise RuntimeError("Unsupported protocol version")
            if req.body.universe != EUniverse.Public:
                raise RuntimeError("Unsupported universe")
        except RuntimeError as e:
            return (await self.disconnect)

        challenge = req.body.challenge
        key, encrypted_key = crypto.session_key(challenge)
        crc = binascii.crc32(encrypted_key) & 0xffffffff

        resp = msg.Message({
            "msg": EMsg.ChannelEncryptResponse,
            "body": {
                "key": encrypted_key,
                "crc": crc
                }
            })

        r = await self.ready(event=EMsg.ChannelEncryptResult, packet=resp)

        if r is None or r.body.eresult != EResult.OK:
            return (await self.disconnect(exc=RuntimeError("Bad CM Server")))

        self._channel_encrypt_key = key

        if challenge:
            self._channel_encrypt_hmac = key[:16]
