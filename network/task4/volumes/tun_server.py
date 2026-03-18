#!/usr/bin/env python3
import fcntl
import ssl

from scapy.all import *


# ==> SOCKET <==
PORT = 9090

RX_IP = "0.0.0.0"
tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_sock.bind((RX_IP, PORT))
tcp_sock.listen()
print("Waiting for TCP connection...")
tcp_conn, _ = tcp_sock.accept()
print("TCP client connected")
ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_ctx.load_cert_chain("./cert.pem", "./key.pem")
ssl_ctx.verify_mode = ssl.CERT_NONE
ssl_sock = ssl_ctx.wrap_socket(tcp_conn, server_side=True)

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
os.system(f"ip addr add 192.168.60.11/24 dev {ifname}")

CLIENT_IP = "10.9.0.5"
os.system(f"ip route add 192.168.53.99 dev {ifname} onlink via {CLIENT_IP}")


while True:
    ready, _, _ = select.select([ssl_sock, tun], [], [])
    for fd in ready:
        if fd is ssl_sock:  # === INBOUND ===
            data = ssl_sock.recv(2048)
            pkt = IP(data)
            print(f"[INBOUND] <==: {pkt.src} --> {pkt.dst}")  # pyright: ignore[reportUnknownMemberType]
            os.write(tun, bytes(pkt))

        if fd is tun:  # === OUTBOUND ===
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print(f"[OUTBOUND] ==>: {pkt.src} --> {pkt.dst}")
            ssl_sock.send(bytes(pkt))
