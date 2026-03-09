import socket
import struct


def main():
    socket_icmp = socket.socket(
        family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP
    )
    socket_icmp.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    while 1:
        packet = socket_icmp.recv(1024)
        # print(packet)
        packet = struct.unpack("!B", packet[0:1])
        print(packet[0] >> 4)  # should be version 4 (4-bit field in IPv4 header)


if __name__ == "__main__":
    main()
