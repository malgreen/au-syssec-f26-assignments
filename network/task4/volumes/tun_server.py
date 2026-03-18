#!/usr/bin/env python3
import fcntl
from scapy.all import *
import ssl
import time

CLIENT_IP = "10.9.0.5"

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
ssl_ctx.load_verify_locations("cert.pem") 
ssl_ctx.load_cert_chain("cert.pem", "key.pem")
ssl_conn = ssl_ctx.wrap_socket(tcp_conn, server_side=True)

# # ==> Rx
# RX_IP = "0.0.0.0"
# rx_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# rx_tcp_sock.bind((RX_IP, PORT))
# rx_tcp_sock.listen()
# rx_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) 
# rx_ssl_ctx.load_cert_chain("cert.pem", "key.pem")
# rx_ssl_sock = rx_ssl_ctx.wrap_socket(rx_tcp_sock, server_side=True)
# rx_conn, rx_addr = rx_ssl_sock.accept()

# # ==> Tx
# tx_tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# # tx_udp_sock.bind((CLIENT_IP, PORT))
# tx_ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) 
# tx_ssl_ctx.load_verify_locations("cert.pem")
# tx_ssl_sock = tx_ssl_ctx.wrap_socket(tx_tcp_sock, server_hostname=CLIENT_IP)
# while True:
#     try:
#         tx_ssl_sock.connect((CLIENT_IP, PORT))
#         print("SSL connected")
#         break # break on successful connection
#     except:
#         time.sleep(1)


# ==> TUN <==
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# ==> Interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'algrn%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))

# ==> Routing
os.system(f"ip link set dev {ifname} up")
os.system(f"ip addr add 192.168.60.11/24 dev {ifname}")
os.system(f"ip route add 192.168.53.99 dev {ifname} onlink via {CLIENT_IP}")


while True:
    ready, _, _ = select.select([ssl_conn, tun], [], [])
    for fd in ready:
        if fd is ssl_conn: # === INBOUND ===
            data = ssl_conn.recv(2048)
            pkt = IP(data)
            print(f"[INBOUND] <==: {pkt.src} --> {pkt.dst}")  # pyright: ignore[reportUnknownMemberType]
            os.write(tun, bytes(pkt))

        if fd is tun: # === OUTBOUND ===
            packet = os.read(tun, 2048)
            pkt = IP(packet)
            print(f"[OUTBOUND] ==>: {pkt.src} --> {pkt.dst}")
            ssl_conn.send(bytes(pkt))

