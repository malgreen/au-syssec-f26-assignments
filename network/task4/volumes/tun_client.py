#!/usr/bin/env python3

import fcntl
import os
import ssl
import struct
import time

from scapy.all import *

# ==> SOCKET <==
SERVER_IP = "10.9.0.11"
SERVER_PORT = 9090

tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
ssl_ctx.load_verify_locations("./cert.pem")
ssl_sock = ssl_ctx.wrap_socket(tcp_sock, server_hostname=SERVER_IP)

while True:
    try:
        print("Trying to connect...")
        ssl_sock.connect((SERVER_IP, SERVER_PORT))
        print("SSL connected")
        break  # just exit the loop on successful connection
    except KeyboardInterrupt:
        exit(0)
    except:
        time.sleep(1)


# ==> TUN <==
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000

# ==> Interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack("16sH", b"tun%d", IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname = ifname_bytes.decode("UTF-8")[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# ==> Routing
os.system(f"ip link set dev {ifname} up")
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip route add 192.168.60.0/24 dev {ifname} onlink via {SERVER_IP}")


while True:
    ready, _, _ = select.select([ssl_sock, tun], [], [])
    for fd in ready:
        if fd is ssl_sock:  # === INBOUND ===
            data = ssl_sock.recv(2048)
            pkt = IP(data)
            print(f"[INBOUND] <==: {pkt.src} --> {pkt.dst}")
            os.write(tun, bytes(pkt))

        if fd is tun:  # === OUTBOUND ===
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print(f"[OUTBOUND] ==>: {pkt.src} --> {pkt.dst}")
            ssl_sock.send(bytes(pkt))
