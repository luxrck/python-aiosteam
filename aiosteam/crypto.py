from hmac import HMAC
from hashlib import sha1
from base64 import b64decode
from os import urandom

from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def encrypt(message, key, secret="", method="base"):
    if method == "base":
        iv = urandom(16)
    elif method == "hmac":
        prefix = urandom(3)
        digest = HMAC(secret, prefix + message, sha1).digest()
        iv = digest[:13] + prefix
    p = len(message) % 16
    if p: message = message + chr(16 - p).encode('ascii') * (16 - p)
    encrypted_iv = AES.new(key, AES.MODE_ECB).encrypt(iv)
    encrypted_msg= AES.new(key, AES.MODE_CBC, iv).encrypt(message)
    return encrypted_iv + encrypted_msg


def decrypt(cyphertext, key, secret="", method="base"):
    iv = AES.new(key, AES.MODE_ECB).decrypt(cyphertext[:16])
    msg= AES.new(key, AES.MODE_CBC, iv).decrypt(cyphertext[16:])
    msg= msg[:len(msg)-msg[-1]]
    if method == "base": return msg
    digest = HMAC(secret, iv[-3:] + msg, sha1).digest()
    if iv[:13] != digest[:13]: return None
    return msg


oaep = PKCS1_OAEP.new(RSA.importKey(b64decode("""
MIGdMA0GCSqGSIb3DQEBAQUAA4GLADCBhwKBgQDf7BrWLBBmLBc1OhSwfFkRf53T
2Ct64+AVzRkeRuh7h3SiGEYxqQMUeYKO6UWiSRKpI2hzic9pobFhRr3Bvr/WARvY
gdTckPv+T1JzZsuVcNfFjrocejN1oWI0Rrtgt4Bo+hOneoo3S57G9F1fOpn5nsQ6
6WOiu4gZKODnFMBCiQIBEQ==
""")))
def session_key(secret=b''):
    key = urandom(32)
    return key, oaep.encrypt(key + secret)
