#!/usr/bin/env python3

import fcntl
import os
import ssl
import struct
import time
import select
import socket

from scapy.all import *

GATEWAY_IP = "10.9.0.11"
INTERFACE_IP = "192.168.53.99"
NETWORK_IP = "192.168.60.0"

SERVER_PORT = 9090

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000


def main():
    tun_dev = setup_tun()
    ssl_sock = setup_ssl()
    while True:
        ready, _, _ = select.select([ssl_sock, tun_dev], [], [])
        for fd in ready:
            if fd is ssl_sock:  # === INBOUND ===
                data = ssl_sock.recv(2048)
                pkt = IP(data)
                print(f"[INBOUND] <==: {pkt.src} --> {pkt.dst}")
                os.write(tun_dev, bytes(pkt))

            if fd is tun_dev:  # === OUTBOUND ===
                packet = os.read(tun_dev, 2048)
                pkt = IP(packet)
                print(f"[OUTBOUND] ==>: {pkt.src} --> {pkt.dst}")
                ssl_sock.send(bytes(pkt))


def setup_tun():
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", b"tun%d", IFF_TUN | IFF_NO_PI)
    ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
    ifname = ifname_bytes.decode("UTF-8")[:16].strip("\x00")
    print("Interface Name: {}".format(ifname))
    os.system(f"ip link set dev {ifname} up")
    os.system(f"ip addr add {INTERFACE_IP}/24 dev {ifname}")
    os.system(f"ip route add {NETWORK_IP}/24 dev {ifname} onlink via {GATEWAY_IP}")
    return tun


def setup_ssl() -> ssl.SSLSocket:
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_verify_locations("./cert.pem")
    ssl_sock = ssl_ctx.wrap_socket(tcp_sock, server_hostname=GATEWAY_IP)
    while True:
        try:
            print("Trying to connect...")
            ssl_sock.connect((GATEWAY_IP, SERVER_PORT))
            print("SSL connected")
            break  # just exit the loop on successful connection
        except KeyboardInterrupt:
            exit(0)
        except:
            time.sleep(1)
    return ssl_sock


if __name__ == "__main__":
    main()
