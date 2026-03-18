#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *
import ssl

# Create UDP sockets
SERVER_IP = "10.9.0.11"
SERVER_PORT = 9090

tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) 
ssl_ctx.load_verify_locations("cert.pem")
ssl_sock = ssl_ctx.wrap_socket(tcp_sock, server_hostname=SERVER_IP)

while True:
    try:
        print("Trying to connect...")
        ssl_sock.connect((SERVER_IP, SERVER_PORT))
        print("SSL connected")
        break # break on successful connection
    except KeyboardInterrupt:
        exit(0)
    except:
        time.sleep(1)



TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000



# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'algrn%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# Setup routing
os.system(f"ip link set dev {ifname} up")
os.system(f"ip addr add 192.168.53.99/24 dev {ifname}")
os.system(f"ip route add 192.168.60.0/24 dev {ifname} onlink via {SERVER_IP}")


while True:
    # this will block until at least one interface is ready
    ready, _, _ = select.select([ssl_sock, tun], [], [])
    for fd in ready:
        if fd is ssl_sock: # === INBOUND ===
            data= ssl_sock.recv(2048)
            pkt = IP(data)
            print(f"From socket <==: {pkt.src} --> {pkt.dst}")
            os.write(tun, bytes(pkt))

        if fd is tun: # === OUTBOUND ===
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print(f"From tun ==>: {pkt.src} --> {pkt.dst}")
            # if pkt:
            ssl_sock.send(packet)
