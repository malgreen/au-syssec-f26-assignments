from pydoc import plain
import socket
import struct

from Crypto.Cipher import AES

AES_KEY = b"e87e570582047b12e8c71b983ee0e075"


def main():
    socket_icmp = socket.socket(
        family=socket.AF_INET, type=socket.SOCK_RAW, proto=socket.IPPROTO_ICMP
    )
    print("--- WAITING FOR MESSAGE ---")
    while 1:
        try:
            packet = socket_icmp.recv(1024)
            if not packet[20] == 47:
                continue
            print("\n--- RECEIVED RECEIVED ---")
            # (IPv4 Header = 20 bytes, ICMP header = 8 bytes, nonce = 16 bytes, tag = 16 bytes, ciphertext = rest)
            nonce = packet[28:44]
            tag = packet[44:60]
            ciphertext = packet[60:]

            aes = AES.new(key=AES_KEY, mode=AES.MODE_GCM, nonce=nonce)

            plaintext = aes.decrypt_and_verify(ciphertext, tag).decode()
            print(plaintext)
            print("-------------------------\n")
            print("--- WAITING FOR MESSAGE ---")
        except Exception as e:
            print(e)
            print("--- WAITING FOR MESSAGE ---")


if __name__ == "__main__":
    main()
