from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes, getPrime, inverse


def main():
    N, d, e = generate_rsa_key()
    message = "Hello, world!"
    message_bytes = message.encode()

    signature = rsa_pss_sign((N, d), message_bytes)

    result = rsa_pss_verify((N, e), message_bytes, signature)

    print("SUCCESS" if result else "FAILURE")


# --- Key Generation ---
def generate_rsa_key() -> (int, int, int):  # N, d, e
    e = 65537
    bits = 3072 // 2  # TODO... idk

    p = getPrime(bits)  # library function to find a prime number of some bit length
    q = getPrime(bits)
    N = p * q

    phi = (p - 1) * (q - 1)

    d = inverse(e, phi)  # library function to find modular multiplicative inverse

    return (N, d, e)


# --- Utilities ---
def ceiling_division(n, d):
    return -(n // -d)


def bytes_xor(x: bytes, y: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(x, y))


def sha256_hash(input: bytes) -> bytes:
    sha = SHA256.new()
    sha.update(input)
    return sha.digest()


# --- Mask Generation Function ---
def mgf1(mgf_seed: str, mask_len: int) -> bytes:
    h_len = 32
    T = bytearray()
    for counter in range(ceiling_division(mask_len, h_len)):
        C = i2osp(counter, 4)
        T += sha256_hash(mgf_seed + C)
    return T[:mask_len]


# --- Data Conversion Primitives ---
def os2ip(s: bytes) -> int:
    return bytes_to_long(s)


def i2osp(x: int, x_len: int) -> str:
    return long_to_bytes(x, x_len)


# --- Signing ---
def emsa_pss_encode(M: bytes, em_bits: int) -> bytes:
    s_len = 32
    em_len = ceiling_division(em_bits, 8)

    m_hash = sha256_hash(M)
    h_len = len(m_hash)
    assert em_len >= h_len + s_len + 2, "encoding error"

    salt = get_random_bytes(s_len)

    M_ = bytes(8) + m_hash + salt
    assert len(M_) == 8 + h_len + s_len, (
        f"invalid M' length. expected {8 + h_len + s_len}, got {len(M_)}"
    )

    H = sha256_hash(M_)
    assert len(H) == h_len

    PS = bytes(em_len - s_len - h_len - 2)

    DB = PS + bytes.fromhex("01") + salt
    assert len(DB) == em_len - h_len - 1

    db_mask = mgf1(H, em_len - h_len - 1)

    masked_DB = bytearray(bytes_xor(DB, db_mask))
    masked_DB[0] &= 0xFF >> (
        8 * em_len - em_bits
    )  # zero out the leftmost bits in the leftmost byte

    EM = masked_DB + H + bytes.fromhex("bc")

    assert len(EM) == em_len, (
        f"incorrect output length. expected {em_len}, got {len(EM)}"
    )
    return EM


def rsa_sp1(K: (int, int), msg_r: int) -> int:
    N, d = K
    assert 0 <= msg_r < N, "message representative out of range"
    return pow(msg_r, d, N)


def rsa_pss_sign(K: (int, int), M: bytes) -> bytes:
    N, d = K
    mod_bits = N.bit_length()
    k = ceiling_division(mod_bits, 8)

    em = emsa_pss_encode(M, mod_bits - 1)

    m = os2ip(em)

    s = rsa_sp1(K, m)

    S = i2osp(s, k)

    assert len(S) == k, f"incorrect signature size. expected {k}, got {len(S)}"
    return S


# --- Verification ---
def rsa_vp1(K: (int, int), s: int) -> int:
    N, e = K
    assert 0 < s < N - 1
    return pow(s, e, N)


def emsa_pss_verify(M: bytes, EM: bytes, em_bits: int) -> bool:
    s_len = 32
    em_len = len(EM)
    m_hash = sha256_hash(M)

    h_len = len(m_hash)

    assert not (em_len < h_len + s_len + 2), "inconsistent"

    assert EM[-1:] == bytes.fromhex("bc"), "inconsistent"

    r = em_len - h_len - 1  # instead of duplicating it three times
    masked_DB = EM[:r]
    H = EM[r : r + h_len]

    assert masked_DB[0] <= (0xFF >> (8 * em_len - em_bits)), "inconsistent"

    db_mask = mgf1(H, em_len - h_len - 1)

    DB = bytearray(bytes_xor(masked_DB, db_mask))

    DB[0] &= 0xFF >> (8 * em_len - em_bits)

    for byte in DB[: em_len - h_len - s_len - 2 - 1]:  # '-1' because of indexing
        assert byte == 0x00, "inconsistent"
    assert DB[em_len - h_len - s_len - 1 - 1] == 0x01, (
        "inconsistent"
    )  # again, '-1' because of indexing

    salt = DB[s_len:]

    M_ = bytes(8) + m_hash + salt

    H_ = sha256_hash(M_)

    assert H != H_, "inconsistent"

    return True


def rsa_pss_verify(K: (int, int), M: bytes, S: bytes) -> bool:
    N, e = K
    mod_bits = N.bit_length()
    k = ceiling_division(mod_bits, 8)

    assert len(S) == k, f"incorrect signature size. expected {k}, got {len(S)}"

    s = os2ip(S)

    m = rsa_vp1(K, s)

    EM = i2osp(m, k)

    return emsa_pss_verify(M, EM, mod_bits - 1)


# --- MAIN ---
if __name__ == "__main__":
    main()
