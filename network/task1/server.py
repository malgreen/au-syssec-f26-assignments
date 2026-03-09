import socket
import struct


def main():
    socket_icmp = socket.socket(
        family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP
    )
    socket_icmp.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    while 1:
        packet = socket_icmp.recv(1024)
        print(packet[28:]) # IPv4 Header = 20 bytes, ICMP header = 8 bytes, content = rest


if __name__ == "__main__":
    main()
