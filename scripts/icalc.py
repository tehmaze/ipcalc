#!/usr/bin/env python

import ipcalc
import argparse


def print_info(subnet):
    print("")
    print(f"Network Information")
    print("*" * 50)
    print(f"Network:\t\t{subnet.network()}")
    print(f"Broadcast:\t\t{subnet.broadcast()}")
    print(f"Netmask:\t\t{subnet.netmask()}")
    print(f"Host Start:\t\t{subnet.host_first()}")
    print(f"Host End:\t\t{subnet.host_last()}")
    print(f"")


def main(prefix):
    try:
        subnet = ipcalc.Network(prefix)

    except ValueError as e:
        print(e)

    print_info(subnet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IP Calculator")
    parser.add_argument("prefix", metavar="PREFIX", type=str)
    args = parser.parse_args()

    main(args.prefix)
