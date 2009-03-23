#!/usr/bin/env python

from distutils.core import setup

long_description = '''
This module allows you to perform IP subnet calculations, there is support
for both IPv4 and IPv6 CIDR notation.
'''

setup(name='ipcalc',
      version='0.3',
      description='IP subnet calculator',
      long_description=long_description,
      author='Wijnand Modderman',
      author_email='python@tehmaze.com',
      url='http://dev.tehmaze.com/projects/ipcalc',
      packages = [''],
      package_dir = {'': 'src'},
     )
