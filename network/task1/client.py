import socket
import struct


def main():
    msg = b"Hello, World!"

    socket_icmp = socket.socket(
        family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP
    )

    # first, we have to construct the header.
    # see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol for details
    # we are going to use reserved type '47'
    type = 47  # field 1 1 byte
    code = 0  # 1 byte
    header = struct.pack(
        "!BBHI", type, code, 0, 0
    )  # B = 1 byte, H = 2 bytes, I = 4 bytes

    checksum = ip_checksum(header + msg)
    header = struct.pack("!BBHI", type, code, checksum, 0)

    packet = header + msg
    address = ("127.0.0.1", 1)  # tuple of (ip, port)

    print(socket_icmp.sendto(packet, address))
    socket_icmp.close()


# def build_header
# def build_body


def ip_checksum(input: bytes) -> int:
    input = input if len(input) % 2 == 0 else input + bytes([0])  # pad if uneven
    output = 0

    words = [  # split into 16-bit words
        int.from_bytes(input[i : i + 2]) for i in range(0, len(input), 2)
    ]

    for word in words:
        # print(word.hex())
        # word_struct.unpack('H', struct.pack('h', int.from_bytes(word)))
        # word_int = int.from_bytes(word)
        # sum += ~word_int
        output += word
        if (output & 0xFFFF) != output:
            output &= 0xFFFF
            output += 1

    # output = (~output) & 0xFFFF
    return (~output) & 0xFFFF


if __name__ == "__main__":
    main()
