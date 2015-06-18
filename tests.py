# -*- coding: utf-8 -*-
import unittest
import ipcalc


class TestNetwork(unittest.TestCase):

    def test_indexers(self):
        network = ipcalc.Network('192.168.11.0/255.255.255.0')
        expected = range(long(0xC0A80B00), long(0xC0A80C00))

        self.assertEqual(network.size(), len(expected))

        for i in xrange(network.size()):
            self.assertEqual(long(network[i]), expected[i])

        self.assertEqual(long(network[-1]), expected[-1])
