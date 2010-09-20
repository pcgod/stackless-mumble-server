#!/bin/env python

from distutils.core import setup, Extension

cryptstate = Extension('cryptstate',
               libraries = ['crypto'],
               extra_compile_args = ["-O2", "-march=native", "-funroll-loops", "-Wall", "-Wextra"],
               sources = ['cryptstate.c'])

packetdatastream = Extension('packetdatastream',
               extra_compile_args = ["-O2", "-march=native", "-funroll-loops", "-Wall", "-Wextra"],
               sources = ['packetdatastream.c'])

setup(name = 'stackless-server-modules',
      version = '0.0.0.1',
      description = 'Stackless server module',
      ext_modules = [cryptstate, packetdatastream])
