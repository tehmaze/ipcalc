import unittest

from ipcalc import IP, Network

class TestSuite(unittest.TestCase):
    """Tests."""

    def test_ipv4_1(self):
        net = Network('192.168.114.42', 23)
        self.assertTrue(str(net) == '192.168.114.42/23')
        self.assertTrue(str(net.to_ipv6().to_compressed()) == '2002:c0a8:722a::')
        self.assertTrue(net.info() == 'PRIVATE')
        self.assertTrue(net.subnet() == 23)
        self.assertTrue(net.size() == 1 << (32 - 23))
        self.assertTrue(int(net) == 0xc0a8722a)
        self.assertTrue(net.hex().lower() == 'c0a8722a')
        self.assertTrue(str(net.netmask()) == '255.255.254.0')
        self.assertTrue(net.version() == 4)
        self.assertTrue(str(net.network()) == '192.168.114.0')
        self.assertTrue(str(net.broadcast()) == '192.168.115.255')
        self.assertFalse('192.168.0.1' in net)
        self.assertTrue('192.168.114.128' in net)
        self.assertFalse('10.0.0.1' in net)
        self.assertTrue(str(net + 6) == '192.168.114.48/23')
        self.assertTrue((net + 6) in net)
        self.assertTrue(str(net - 6) == '192.168.114.36/23')
        self.assertTrue((net - 6) in net)

    def test_ipv4_2(self):
        net = Network('10.10.0.0', '255.255.255.0')
        self.assertTrue(str(net) == '10.10.0.0/24')
        self.assertTrue(str(net.to_ipv6().to_compressed()) == '2002:a0a::')
        self.assertTrue(net.info() == 'PRIVATE')
        self.assertTrue(net.subnet() == 24)
        self.assertTrue(net.size() == 1 << (32 - 24))
        self.assertTrue(int(net) == 0x0a0a0000)
        self.assertTrue(net.hex().lower() == '0a0a0000')
        self.assertTrue(str(net.netmask()) == '255.255.255.0')
        self.assertTrue(net.version() == 4)
        self.assertTrue(str(net.network()) == '10.10.0.0')
        self.assertTrue(str(net.broadcast()) == '10.10.0.255')
        self.assertFalse('192.168.0.1' in net)
        self.assertFalse('192.168.114.128' in net)
        self.assertFalse('10.0.0.1' in net)
        self.assertTrue('10.10.0.254' in net)
        self.assertTrue('10.10.0.100' in net)
        self.assertTrue(str(net + 6) == '10.10.0.6/24')
        self.assertTrue(str(net + 6) in net)
        self.assertTrue(str(net - 6) == '10.9.255.250/24') # note, result is not in subnet
        self.assertFalse(str(net -6) in net)

    def test_ipv4_3(self):
        net = Network('10.10.0.0/255.255.255.0')
        self.assertTrue(str(net) == '10.10.0.0/24')
        self.assertTrue(str(net.to_ipv6().to_compressed()) == '2002:a0a::')
        self.assertTrue(net.info() == 'PRIVATE')
        self.assertTrue(net.subnet() == 24)
        self.assertTrue(net.size() == 1 << (32 - 24))
        self.assertTrue(int(net) == 0x0a0a0000)
        self.assertTrue(net.hex().lower() == '0a0a0000')
        self.assertTrue(str(net.netmask()) == '255.255.255.0')
        self.assertTrue(net.version() == 4)
        self.assertTrue(str(net.network()) == '10.10.0.0')
        self.assertTrue(str(net.broadcast()) == '10.10.0.255')
        self.assertFalse('192.168.0.1' in net)
        self.assertFalse('192.168.114.128' in net)
        self.assertFalse('10.0.0.1' in net)
        self.assertTrue('10.10.0.254' in net)
        self.assertTrue('10.10.0.100' in net)

    def test_ipv6_1(self):
        net = Network('123::', 128)
        self.assertTrue(str(net) == '0123:0000:0000:0000:0000:0000:0000:0000/128')
        self.assertTrue(str(net.to_compressed()) == '123::')
        self.assertTrue(str(net.to_ipv6().to_compressed()) == '123::')
        self.assertTrue(net.info() == 'UNKNOWN')
        self.assertTrue(net.subnet() == 128)
        self.assertTrue(net.size() == 1 << (128 - 128))
        self.assertTrue(int(net) == (0x123<<112))
        self.assertTrue(net.hex().lower() == '01230000000000000000000000000000')
        self.assertTrue(str(net.netmask()) == 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff')
        self.assertTrue(net.version() == 6)
        self.assertTrue(str(net.network()) == '0123:0000:0000:0000:0000:0000:0000:0000')
        self.assertTrue(str(net.broadcast()) == '0123:0000:0000:0000:0000:0000:0000:0000')
        self.assertFalse('123:456::' in net)
        self.assertTrue('123::' in net)
        self.assertFalse('::1' in net)
        self.assertFalse('123::456' in net)
        self.assertTrue(str((net + 6).to_compressed()).lower() == '123::6')
        self.assertFalse((net + 6) in net)
        self.assertTrue(str((net - 6).to_compressed()).lower() == '122:ffff:ffff:ffff:ffff:ffff:ffff:fffa')
        self.assertFalse((net - 6) in net)

    def test_ipv6_2(self):
        net = Network('::42', 64)
        self.assertTrue(str(net) == '0000:0000:0000:0000:0000:0000:0000:0042/64')
        self.assertTrue(str(net.to_compressed()) == '::42')
        self.assertTrue(str(net.to_ipv6().to_compressed()) == '::42')
        self.assertTrue(net.info() == 'IPV4COMP')
        self.assertTrue(net.subnet() == 64)
        self.assertTrue(net.size() == 1 << (128 - 64))
        self.assertTrue(int(net) == 0x42)
        self.assertTrue(net.hex().lower() == '00000000000000000000000000000042')
        self.assertTrue(str(net.netmask()) == 'ffff:ffff:ffff:ffff:0000:0000:0000:0000')
        self.assertTrue(net.version() == 6)
        self.assertTrue(str(net.network()) == '0000:0000:0000:0000:0000:0000:0000:0000')
        self.assertTrue(str(net.broadcast()) == '0000:0000:0000:0000:ffff:ffff:ffff:ffff')
        self.assertFalse('123:456::' in net)
        self.assertTrue('::aaaa:bbbb:cccc:dddd' in net)
        self.assertTrue('::dddd' in net)
        self.assertTrue('::1' in net)
        self.assertFalse('123::456' in net)
        self.assertTrue(str((net + 6).to_compressed()).lower() == '::48')
        self.assertTrue((net + 6) in net)
        self.assertTrue(str((net - 6).to_compressed()).lower() == '::3c')
        self.assertTrue((net - 6) in net)

    def test_ipv6_3(self):
        net = Network('2001:dead:beef:1:c01d:c01a::', 48)
        self.assertTrue(str(net) == '2001:dead:beef:0001:c01d:c01a:0000:0000/48')
        self.assertTrue(str(net.to_compressed()) == '2001:dead:beef:1:c01d:c01a::')
        self.assertTrue(str(net.to_ipv6().to_compressed()) == '2001:dead:beef:1:c01d:c01a::')
        self.assertTrue(net.info() == 'UNKNOWN')
        self.assertTrue(net.subnet() == 48)
        self.assertTrue(net.size() == 1 << (128 - 48))
        self.assertTrue(int(net) == 0x2001deadbeef0001c01dc01a00000000)
        self.assertTrue(net.hex().lower() == '2001deadbeef0001c01dc01a00000000')
        self.assertTrue(str(net.netmask()) == 'ffff:ffff:ffff:0000:0000:0000:0000:0000')
        self.assertTrue(net.version() == 6)
        self.assertTrue(str(net.network()) == '2001:dead:beef:0000:0000:0000:0000:0000')
        self.assertTrue(str(net.broadcast()) == '2001:dead:beef:ffff:ffff:ffff:ffff:ffff')
        self.assertFalse('123:456::' in net)
        self.assertFalse('::aaaa:bbbb:cccc:dddd' in net)
        self.assertFalse('::dddd' in net)
        self.assertFalse('::1' in net)
        self.assertFalse('123::456' in net)
        self.assertTrue('2001:dead:beef:babe::1234' in net)

    def test_ipv6_4(self):
        net = Network('2001:dead:beef:1:c01d:c01a::', 'ffff:ffff:ffff::')
        self.assertTrue(str(net) == '2001:dead:beef:0001:c01d:c01a:0000:0000/48')
        self.assertTrue(str(net.to_compressed()) == '2001:dead:beef:1:c01d:c01a::')
        self.assertTrue(str(net.to_ipv6().to_compressed()) == '2001:dead:beef:1:c01d:c01a::')
        self.assertTrue(net.info() == 'UNKNOWN')
        self.assertTrue(net.subnet() == 48)
        self.assertTrue(net.size() == 1 << (128 - 48))
        self.assertTrue(int(net) == 0x2001deadbeef0001c01dc01a00000000)
        self.assertTrue(net.hex().lower() == '2001deadbeef0001c01dc01a00000000')
        self.assertTrue(str(net.netmask()) == 'ffff:ffff:ffff:0000:0000:0000:0000:0000')
        self.assertTrue(net.version() == 6)
        self.assertTrue(str(net.network()) == '2001:dead:beef:0000:0000:0000:0000:0000')
        self.assertTrue(str(net.broadcast()) == '2001:dead:beef:ffff:ffff:ffff:ffff:ffff')
        self.assertFalse('123:456::' in net)
        self.assertFalse('::aaaa:bbbb:cccc:dddd' in net)
        self.assertFalse('::dddd' in net)
        self.assertFalse('::1' in net)
        self.assertFalse('123::456' in net)
        self.assertTrue('2001:dead:beef:babe::1234' in net)

    def test_ipv6_5(self):
        # test parsing of 4-in-6 IPv6 address
        ip = IP('8000::0.0.0.1')
        self.assertTrue(ip.ip == ((2**127) + 1))
        ip = IP('8000:8000::0.0.0.1')
        self.assertTrue(ip.ip == ((2**127) + (2**111) + 1))


class TestIP(unittest.TestCase):

    """Tests for IP."""

    def test_eq_le_gt(self):
        self.assertEqual(IP('192.168.11.0'), IP('192.168.11.0'))
        self.assertNotEqual(IP('192.168.1.0'), IP('192.168.11.0'))

    def test_guesstimation(self):
        self.assertEqual(IP('192.168.0.1', mask=28).guess_network(), Network('192.168.0.0/28'))
        self.assertEqual(IP('192.168.0.1/24').guess_network(), Network('192.168.0.0/24'))
        self.assertEqual(IP('192.168.0.1/255.255.255.0', mask=28).guess_network(), Network('192.168.0.0/24'))
        self.assertEqual(IP('192.168.0.56', mask=26).guess_network(), Network('192.168.0.0/26'))
        self.assertEqual(IP('192.168.0.1').guess_network(), Network('192.168.0.1/32'))


class TestNetwork(unittest.TestCase):

    """Tests for Network."""

    def setUp(self):
        self.network = Network('192.168.11.0/255.255.255.0')

    def test_calculation(self):
        self.assertEqual(self.network[1].subnet(), 24)

        a = Network('192.168.0.100/28')
        self.assertEqual(str(a), '192.168.0.100/28')
        self.assertEqual(a.size(), 16)
        self.assertEqual(a.size(), len(a))
        self.assertEqual(long(a), 0xC0A80064)
        for i in xrange(a.size()):
            self.assertEqual(long(a[i]), i + 0xC0A80064)

        self.assertRaises(IndexError, lambda: a[a.size()])

    def test_indexers(self):
        expected = range(long(0xC0A80B00), long(0xC0A80C00))
        self.assertEqual(self.network.size(), len(expected))
        for i in xrange(self.network.size()):
            self.assertEqual(long(self.network[i]), expected[i])
        self.assertEqual(long(self.network[-1]), expected[-1])

    def test_contains(self):
        self.assertTrue(IP('192.168.11.0') in self.network)
        self.assertTrue(IP('192.168.11.1') in self.network)
        self.assertTrue(IP('192.168.11.255') in self.network)

    def test_eq_le_gt(self):
        self.assertEqual(Network('192.168.11.0'), Network('192.168.11.0'))
        self.assertEqual(Network('192.168.11.0/32'), Network('192.168.11.0'))
        self.assertEqual(Network('192.168.11.0'), IP('192.168.11.0'))
        self.assertEqual(Network('192.168.11.0/32'), IP('192.168.11.0'))

        self.assertNotEqual(Network('192.168.11.0/28'), Network('192.168.11.0/24'))
        self.assertNotEqual(Network('192.168.11.0'), Network('192.168.11.1'))
        self.assertNotEqual(Network('192.168.11.0'), Network('192.168.2.1'))
        self.assertNotEqual(Network('192.168.11.0/30'), IP('192.168.11.0'))
        self.assertNotEqual(Network('192.168.1.0'), IP('192.168.11.0'))

        self.assertTrue(Network('192.168.1.0/30') < Network('192.168.1.0/29'))
        self.assertTrue(Network('192.168.1.0/30') <= Network('192.168.1.0/29'))
        self.assertTrue(Network('192.168.1.0/30') <= Network('192.168.1.0/30'))

        self.assertTrue(Network('192.168.1.0/28') > Network('192.168.1.0/29'))
        self.assertTrue(Network('192.168.1.0/28') >= Network('192.168.1.0/29'))
        self.assertTrue(Network('192.168.1.0/28') >= Network('192.168.1.0/28'))


if __name__ == '__main__':
    unittest.main()
