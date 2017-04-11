#!/usr/bin/env python
import aiosteam
from distutils.core import setup


setup(name='python-aiosteam',
      version=aiosteam.__version__,
      description='A steam client with python asyncio.',
      author='lux.r.ck',
      author_email='lux.r.ck@gmail.com',
      packages=['aiosteam'],
      include_package_data=True,
      license="MIT License"
     )
