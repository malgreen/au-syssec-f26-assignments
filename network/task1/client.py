import socket
import struct
from Crypto.Cipher import AES

AES_KEY = b"e87e570582047b12e8c71b983ee0e075"


def main():
    addr = input("\n--- Input IP Address ---\n")
    # is there some way to check it is valid?

    msg = input("--- Input Message ---\n")

    aes = AES.new(key=AES_KEY, mode=AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(msg.encode())
    body = bytes(aes.nonce) + tag + ciphertext

    # first, we have to construct the header
    # see https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol for details
    # we are going to use reserved type '47'
    # struct chars: B = 1 byte, H = 2 bytes, I = 4 bytes
    type = 47  # 1 byte
    code = 0  # 1 byte
    header = struct.pack("!BBHI", type, code, 0, 0)

    checksum = ip_checksum(header + body)
    header = struct.pack("!BBHI", type, code, checksum, 0)

    packet = header + body

    socket_icmp = socket.socket(
        family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP
    )
    try:
        if socket_icmp.sendto(packet, (addr, 1)):
            print("--- Message Sent ---")
        else:
            raise Exception("Unknown Error")
    except Exception as e:
        print(e)    
    socket_icmp.close()

    main()


def ip_checksum(input: bytes) -> int:
    input = input if len(input) % 2 == 0 else input + bytes([0])  # pad if uneven
    output = 0

    words = [  # split into 16-bit words
        int.from_bytes(input[i : i + 2], "big")
        for i in range(
            0,
            len(input),
            2,
        )
    ]

    for word in words:
        output += word
        if (output & 0xFFFF) != output:
            output &= 0xFFFF
            output += 1

    return (~output) & 0xFFFF


if __name__ == "__main__":
    main()
