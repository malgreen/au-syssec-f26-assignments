#!/usr/bin/env python3
import fcntl
from re import sub
import ssl
import os
import subprocess
from scapy.all import *
import socket
import select
import struct

PORT = 9090
GATEWAY_IP = "10.9.0.5"
INTERFACE_IP = "192.168.60.11"
NETWORK_IP = "192.168.53.99"
LISTEN_IP = "0.0.0.0"
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
                print(f"[INBOUND] <==: {pkt.src} --> {pkt.dst}")  # pyright: ignore[reportUnknownMemberType]
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
    os.system(f"ip route add {NETWORK_IP} dev {ifname} onlink via {GATEWAY_IP}")
    return tun


def setup_ssl() -> ssl.SSLSocket:
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.bind((LISTEN_IP, PORT))
    tcp_sock.listen()
    print("Waiting for TCP connection...")
    tcp_conn, _ = tcp_sock.accept()
    print("TCP client connected")
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain("./cert.pem", "./key.pem")
    ssl_sock = ssl_ctx.wrap_socket(tcp_conn, server_side=True)
    return ssl_sock


if __name__ == "__main__":
    main()
