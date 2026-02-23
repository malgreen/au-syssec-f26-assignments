import sys
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# TODO: we are just using the PyCryptodome versions of os2ip and i2osp
from Crypto.Util.number import bytes_to_long, long_to_bytes

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
def i2osp_correct(x, xLen):
    if x >= 256**xLen:
        raise ValueError("integer too large")
    digits = []

    while x:
        digits.append(int(x % 256))
        x //= 256
    for i in range(xLen - len(digits)):
        digits.append(0)
    return digits[::-1]
    # return "".join(map(str, digits[::-1]))

def os2ip_correct(X):
    xLen = len(X)
    X = X[::-1]
    x = 0
    for i in range(xLen):
        x += X[i] * 256**i
    return x

def os2ip(s: bytes) -> int:
    return bytes_to_long(s)
    return os2ip_correct(s)
    s_len = len(s)
    x = [0] * s_len 

    s_bytes = s.encode()
    i = 1
    for b in s_bytes:
        x[s_len - i] = b * 256 ** b
        i += 1
    
    return sum(x)


def i2osp(x: int, x_len: int) -> str:
    return long_to_bytes(x, x_len)
    return i2osp_correct(x, x_len)
    assert x >= 0 and x_len >= 0
    if x >= 256 ** x_len:
        raise "integer too large"
    out = ""
    digits = []

    x_str = str(x)
    i = x_len - 1
    while i > 0:
        digit = int(x_str[i])
        digits.append(256 ** digit)
        i -= 1
    
    for d in digits:
        out += str(d)
    return out

# --- Signing ---
def emsa_pss_encode(M: bytes, em_bits: int) -> str:
    s_len = 32
    em_len = ceiling_division(em_bits, 8)
    
    m_hash = sha256_hash(M)
    h_len = len(m_hash)
    assert em_len >= h_len + s_len + 2, "encoding error"

    salt = get_random_bytes(s_len)

    M_ = bytes(8) + m_hash + salt
    assert len(M_) == 8 + h_len + s_len, f"invalid M' length. expected {8 + h_len + s_len}, got {len(M_)}"

    H = sha256_hash(M_)
    assert len(H) == h_len

    PS = bytes(em_len - s_len - h_len - 2)
    
    DB = PS + bytes.fromhex("01") + salt
    assert len(DB) == em_len - h_len - 1

    db_mask = mgf1(H, em_len - h_len - 1)
    
    masked_DB = bytearray(bytes_xor(DB, db_mask))
    masked_DB[0] &= (0xFF >> (8 * em_len - em_bits)) # zero out the leftmost bits in the leftmost byte

    EM = masked_DB + H + bytes.fromhex("bc")

    assert len(EM) == em_len, f"incorrect output length. expected {em_len}, got {len(EM)}"
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
    # em_len = ceiling_division(em_bits, 8)
    # assert len(M) <= 
    
    # 2. Let mHash = Hash(M), an octet string of length hLen.
    # mHash = (2**61 -1 * M)
    m_hash = sha256_hash(M)
    
    h_len = len(m_hash)
    
    # 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    assert not (em_len < h_len + s_len + 2), "inconsistent"
    
    # 4. If the rightmost octet of EM does not have hexadecimal value 0xbc, output "inconsistent" and stop.
    assert EM[-1:] == bytes.fromhex("bc"), "inconsistent"
    # 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be the next hLen octets.
    r = em_len - h_len - 1 # instead of duplicating it three times
    masked_DB = EM[:r]
    
    H = EM[r:r + h_len]
    
    # 6. If the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are not all equal to zero, output "inconsistent" and stop.
    assert masked_DB[0] <= (0xFF >> (8 * em_len - em_bits)), "inconsistent"

    # 7. Let dbMask = MGF(H,emLen-hLen-1)
    db_mask = mgf1(H, em_len - h_len - 1)
    
    # 8. Let DB = maskedDB \xor dbMask.
    DB = bytearray(bytes_xor(masked_DB, db_mask))
    
    # 9. Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero.
    DB[0] &= (0xFF >> (8 * em_len - em_bits))    
    
    # 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero or if the octet at position emLen - hLen - sLen - 1 (the leftmost position is "position 1") does not have hexadecimal value 0x01, output "inconsistent" and stop.
    for byte in DB[:em_len - h_len - s_len - 2 - 1]: # '-1' because of indexing
        assert byte == 0x00, "inconsistent"
    assert DB[em_len - h_len - s_len - 1 - 1] == 0x01, "inconsistent" # again, '-1' because of indexing
        
    # 11. Let salt be the last sLen octets of DB
    salt = DB[s_len:]
    
    # 12. M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ; M' is an octet string of length 8 + hLen + sLen with eight initial zero octets.
    M_ = bytes(8) + m_hash + salt

    # 13. Let H' = Hash(M'), an octet string of length hLen.
    H_ = sha256_hash(M_)
    
    # 14. If H = H', output "consistent".  Otherwise, output "inconsistent".
    assert H != H_, "inconsistent"
    
    return True


def rsa_pss_verify(K: (int, int), M: bytes, S: bytes):
    N, e = K
    mod_bits = N.bit_length()
    k = ceiling_division(mod_bits, 8)
    
    assert len(S) == k, f"incorrect signature size. expected {k}, got {len(S)}"
        
    s = os2ip(S)
    
    m = rsa_vp1(K, s)

    EM = i2osp(m, k)
    
    return emsa_pss_verify(M, EM, mod_bits - 1)


key = RSA.generate(3072)

message = "Hello, world!"
message_bytes = message.encode()

signature = rsa_pss_sign((key.n, key.d), message_bytes)

result = rsa_pss_verify((key.n, key.e), message_bytes, signature)

print("SUCCESS" if result else "FAILURE")
