#!/usr/bin/env python

from distutils.core import setup

setup(name='ipcalc',
      version='0.4',
      description='IP subnet calculator',
      long_description=file('README.rst').read(),
      author='Wijnand Modderman',
      author_email='python@tehmaze.com',
      url='http://tehmaze.github.com/ipcalc',
      packages = [''],
      package_dir = {'': 'src'},
     )
