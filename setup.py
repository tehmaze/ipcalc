#!/usr/bin/env python

from distutils.core import setup

setup(name='ipcalc',
      version='1.0.0',
      description='IP subnet calculator',
      long_description='''
About
=====

This module allows you to perform IP subnet calculations, there is support for
both IPv4 and IPv6 CIDR notation.

Example Usage
=============

::

    >>> import ipcalc
    >>> for x in ipcalc.Network('172.16.42.0/30'):
    ...     print str(x)
    ...
    172.16.42.0
    172.16.42.1
    172.16.42.2
    172.16.42.3
    >>> subnet = ipcalc.Network('2001:beef:babe::/48')
    >>> print str(subnet.network())
    2001:beef:babe:0000:0000:0000:0000:0000
    >>> print str(subnet.netmask())
    ffff:ffff:ffff:0000:0000:0000:0000:0000
    >>> '192.168.42.23' in Network('192.168.42.0/24')
    True
    >>> long(IP('fe80::213:ceff:fee8:c937'))
    338288524927261089654168587652869703991L

Bugs/Features
=============

You can issue a ticket in GitHub: https://github.com/tehmaze/ipcalc/issues

Documentation
=============

Documentation is available from http://ipcalc.rtfd.org/
''',
      author='Wijnand Modderman-Lenstra',
      author_email='maze@pyth0n.org',
      url='http://tehmaze.github.com/ipcalc/',
      packages = [''],
      package_dir = {'': 'src'},
     )
