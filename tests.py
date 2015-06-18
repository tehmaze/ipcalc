# -*- coding: utf-8 -*-
import unittest
import ipcalc


class TestNetwork(unittest.TestCase):

    def setUp(self):
        self.network = ipcalc.Network('192.168.11.0/255.255.255.0')

    def test_calculation(self):
        self.assertEqual(self.network[1].subnet(), 24)

    def test_indexers(self):
        expected = range(long(0xC0A80B00), long(0xC0A80C00))
        self.assertEqual(self.network.size(), len(expected))
        for i in xrange(self.network.size()):
            self.assertEqual(long(self.network[i]), expected[i])
        self.assertEqual(long(self.network[-1]), expected[-1])

    def test_contains(self):
        self.assertTrue(ipcalc.IP('192.168.11.0') in self.network)
        self.assertTrue(ipcalc.IP('192.168.11.1') in self.network)
        self.assertTrue(ipcalc.IP('192.168.11.255') in self.network)


if __name__ == '__main__':
    unittest.main()