#!/usr/bin/env python
import aiosteam
from setuptools import setup


setup(name='aiosteam',
      version=aiosteam.__version__,
      description='A steam client with python asyncio.',
      author='lux.r.ck',
      author_email='lux.r.ck@gmail.com',
      packages=['aiosteam', 'aiosteam.enums', 'aiosteam.protobufs'],
      install_requires=[
        "aiohttp",
        "pycrypto",
        "protobuf"
        ],
      include_package_data=True,
      license="MIT License",
      zip_safe=False,
     )
