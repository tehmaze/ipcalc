# -*- coding: utf-8 -*-
import unittest
from ipcalc import Network, IP


class TestNetwork(unittest.TestCase):

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


class TestIP(unittest.TestCase):

    def test_eq_le_gt(self):
        self.assertEqual(IP('192.168.11.0'), IP('192.168.11.0'))
        self.assertNotEqual(IP('192.168.1.0'), IP('192.168.11.0'))

    def test_guesstimation(self):
        self.assertEqual(IP('192.168.0.1', mask=28).guess_network(), Network('192.168.0.0/28'))
        self.assertEqual(IP('192.168.0.1/24').guess_network(), Network('192.168.0.0/24'))
        self.assertEqual(IP('192.168.0.1/255.255.255.0', mask=28).guess_network(), Network('192.168.0.0/24'))
        self.assertEqual(IP('192.168.0.56', mask=26).guess_network(), Network('192.168.0.0/26'))
        self.assertEqual(IP('192.168.0.1').guess_network(), Network('192.168.0.1/32'))


if __name__ == '__main__':
    unittest.main()