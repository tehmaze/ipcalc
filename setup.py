#!/usr/bin/env python

from distutils.core import setup
import os

scripts = [os.path.join("scripts", "icalc.py")]
setup(
    name="ipcalc",
    version="1.99.1",
    description="IP subnet calculator",
    scripts=scripts,
    long_description="""
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
    172.16.42.1
    172.16.42.2
    >>> subnet = ipcalc.Network('2001:beef:babe::/48')
    >>> print str(subnet.network())
    2001:beef:babe:0000:0000:0000:0000:0000
    >>> print str(subnet.netmask())
    ffff:ffff:ffff:0000:0000:0000:0000:0000
    >>> '192.168.42.23' in Network('192.168.42.0/24')
    True
    >>> long(IP('fe80::213:ceff:fee8:c937'))
    338288524927261089654168587652869703991L

A convenice script has been added for doing basic command line checks, icalc.py.

::

    $ icalc.py 192.168.0.1/25

    Network Information
    **************************************************
    Network:                192.168.0.0
    Broadcast:              192.168.0.127
    Netmask:                255.255.255.128
    Host Start:             192.168.0.1
    Host End:               192.168.0.126


    $ icalc.py 2001:db8:0:1000::/64

    Network Information
    **************************************************
    Network:                2001:0db8:0000:1000:0000:0000:0000:0000
    Broadcast:              2001:0db8:0000:1000:ffff:ffff:ffff:ffff
    Netmask:                ffff:ffff:ffff:ffff:0000:0000:0000:0000
    Host Start:             2001:0db8:0000:1000:0000:0000:0000:0001
    Host End:               2001:0db8:0000:1000:ffff:ffff:ffff:fffe


Bugs/Features
=============

You can issue a ticket in GitHub: https://github.com/tehmaze/ipcalc/issues

Documentation
=============

Documentation is available from http://ipcalc.rtfd.org/
""",
    author="Wijnand Modderman-Lenstra",
    author_email="maze@pyth0n.org",
    url="https://github.com/tehmaze/ipcalc/",
    py_modules=["ipcalc"],
    install_requires=["six"],
)
