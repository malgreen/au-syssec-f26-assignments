import sys
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# TODO: we are just using the PyCryptodome versions of os2ip and i2osp
from Crypto.Util.number import bytes_to_long, long_to_bytes



def byte_length(input: int) -> int:
    return (input.bit_length() + 7) // 8

def sha256_hash(input: bytes) -> bytes:
    sha = SHA256.new()
    sha.update(input)
    return sha.digest()

def mgf1(mgf_seed: str, mask_len: int) -> str:
    h_len = 32
    T = ""
    for counter in range((mask_len // h_len) - 1):
        C = i2osp(counter, 4)
        T += str(sha256_hash(mgf_seed + C))
    return T[:mask_len]


def bytes_xor(x: bytes, y: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(x, y))
    # out = bytearray(x if len(x) >= len(y) else y)
    # # print(y)
    # for i, b in enumerate(y if len(x) >= len(y) else x):
    #     out[i] ^= b
    # return out

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

def emsa_pss(M: bytes, em_bits: int) -> str:
    s_len = 32
    em_len = em_bits // 8
    
    m_hash = sha256_hash(M.encode())
    h_len = len(m_hash)
    if em_len < h_len + s_len + 2:
        raise "encoding error" 

    salt = get_random_bytes(s_len)

    # M_ = bytearray()
    # M_.extend(bytes(8)) # (0x)00 00 00 00 00 00 00 00
    # M_.extend(m_hash)
    # M_.extend(salt)
    M_ = bytes(8) + m_hash + salt
    assert len(M_) == 8 + h_len + s_len, f"invalid M' length. expected {8 + h_len + s_len}, got {len(M_)}"


    H = sha256_hash(M_)
    assert len(H) == h_len

    PS = bytearray(em_len - s_len - h_len - 2)

    # DB = bytearray()
    # DB.extend(PS)
    # DB.extend(bytes(0x01))
    # DB.extend(salt)
    DB = PS + bytes.fromhex("01") + salt
    assert len(DB) == em_len - h_len - 1

    db_mask = mgf1(H, em_len - h_len - 1)
    
    masked_DB = bytearray(bytes_xor(DB, db_mask.encode()))
    masked_DB[0] &= (0xFF >> (8 * em_len - em_bits)) # zero out the leftmost bits in the leftmost byte
    # TODO: incorrect
    # masked_DB = bytes(1) + masked_DB[1:]  

    # EM = bytearray()
    # EM.extend(masked_DB)
    # EM.extend(H)
    # EM.extend(bytes(0xbc))
    EM = masked_DB + H + bytes.fromhex("bc")

    assert len(EM) == em_len, f"incorrect output length. expected {em_len}, got {len(EM)}"
    return EM

def rsa_sp1(K: (int, int), msg_r: int) -> int:
    N, d = K
    assert 0 <= msg_r < N, "message representative out of range"
    return pow(msg_r, d, N)

def rsa_pss_sign(K: (int, int), M: str) -> bytes:
    N, d = K
    k = byte_length(N)
    mod_bits = N.bit_length()
    
    em = emsa_pss(M, mod_bits - 1)
    print(em[-1:].hex())

    m = os2ip(em)
    
    s = rsa_sp1(K, m)
    
    S = i2osp(s, k)
    print(S[-1:].hex())
    assert len(S) == k, f"incorrect signature size. expected {k}, got {len(S)}"
    return S

# Signature verification
def RSASSA_PSS_VERIFY(n:int,e:int,M: bytes,S: bytes):
    k = byte_length(n)
    mod_bits = n.bit_length()
    assert len(S) == k, f"incorrect signature size. expected {k}, got {len(S)}"
        
    s = os2ip(S)
    
    m = RSAVP1(n,e,s)
    
    EM = i2osp(m, k)
    print(EM[-1:].hex())
    
    Result = EMSA_PSS_VERIFY(M, EM, mod_bits - 1)
    
    if Result: 
        print("Verified")
    else:
        print("Failed verification")
    
    
def RSAVP1(n: int, e: int , s: int) -> int:
    if (0 > s & s > n - 1):
        exit("RSAVP1: Signature representative out of range")
    
    #m: int = (s ** e) % n
    m: int = pow(s, e, n)
    
    return m
        

def EMSA_PSS_VERIFY(M: bytes, EM: bytes, em_bits: int) -> bool:
    s_len = 32
    em_len = len(EM)
    # assert len(M) <= 
    
    # 2. Let mHash = Hash(M), an octet string of length hLen.
    # mHash = (2**61 -1 * M)
    m_hash = sha256_hash(M.encode())
    
    h_len = len(m_hash)
    
    # 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
    assert not (em_len < h_len + s_len + 2), "inconsistent"
    
    # 4. If the rightmost octet of EM does not have hexadecimal value 0xbc, output "inconsistent" and stop.
    assert EM[len(EM) - 1] == bytes.fromhex("bc"), "inconsistent"
        
    # 5. Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be the next hLen octets.
    masked_DB = EM[:em_len - h_len - 1]
    
    H = EM[em_len - h_len - 1:]
    
    # 6. If the leftmost 8emLen - emBits bits of the leftmost octet in maskedDB are not all equal to zero, output "inconsistent" and stop.
    assert masked_DB[0] == (0xFF >> (8 * em_len - em_bits)), "inconsistent" # TODO?
    
    # 7. Let dbMask = MGF(H,emLen-hLen-1)
    db_mask = mgf1(H, em_len - h_len - 1)

    # 8. Let DB = maskedDB \xor dbMask.
    DB = bytes_xor(masked_DB, db_mask)
    
    # 9. Set the leftmost 8emLen - emBits bits of the leftmost octet in DB to zero.
    DB &= (0xFF >> (8 * em_len - em_bits))    
    
    # 10. If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero or if the octet at position emLen - hLen - sLen - 1 (the leftmost position is "position 1") does not have hexadecimal value 0x01, output "inconsistent" and stop.
    for byte in DB[:em_len - h_len - s_len - 2]:
        if byte != 0x00: 
            raise "inconsistent"
    assert DB[em_len - h_len - s_len - 1] == 0x01, "inconsistent"
        
    # 11. Let salt be the last sLen octets of DB
    salt = DB[s_len:]
    
    # 12. M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ; M' is an octet string of length 8 + hLen + sLen with eight initial zero octets.
    M_ = bytes.fromhex("0000000000000000") + m_hash + salt

    # 13. Let H' = Hash(M'), an octet string of length hLen.
    H_ = sha256_hash(M_)
    
    # 14. If H = H', output "consistent".  Otherwise, output "inconsistent".
    assert H != H_, "inconsistent"
    
    print("consistent")
    return True
        
       

key = {
    "N": 371889671565463942367954290447998038346508378412906393777224051429051866836270954172499990068084527065676474226497111078968545581678986502752163234735983816266651693007104629564770588543440325988804899244026631454677152614550651753904265619022279606900854783220794261348526584500572594674241974376658646262189145567709769283251762560694400572465726082170701222210125885879948029487762112037364302466621095872978842538310928567591123149566093238885840827787725484819592305856326685166124473340756939283273191368795635230585057700831386876568628042763954626872483226230726070327952344844951558544115548586636052706914014075072597547439479078647882373329479504585286691260425177891094162273338040018179134808494455923922717948840276144321923065878921845420515282024665589279942270471448095668407812152450984626338832634493655952560368436225132213475907022280926435314387018516054719994558495487875943756155686597582159926754401125523324782051873744809420732606183411460067830997859604055522162664350947395824442728925713410041007101654162502467551010035917636120605311839200181621229630617301263497489510018550869800755860897410215159281789917201419826531657145964968297805989867061674852348721636750658827357413205101488792521091589981404570296658441503336458633338300985575834647724288265282075539621587480939642528645512718665635452724107573834271459600842563974109351704846578828052291579660479831933733829817544636651156032908222750063965543826732409413035742157829582222252734488171239821643196742895521745046223816042173861970296931343093,
    "e": 65537,
    "d": 704568893365996414634381564099738149008766018880352583250389516986117849511017078933561484164113512626663658894202079519073224826025284515707073968013356123473720716016177814049268991090563241641173826085736881908481665803073543531470464884600780249891002443123159680922256356992984726021689282602303480295260508949763781626218862260306314935121554769895436304867857472899533236069096837472290866690721678555475033014522085560753995500147374230067033109511648948556293212483692514318203063250750499374696054423093087230666665193359812156617175163800422695919354373048267301268419249907457651114182355953189601619513839264336154715153143181760327057682901353432608272230770333279835817092659376585627242871270763190026448575121249167925520900626946692100223477766446675500698219892577482685806648569534530985175051992333296150184354063500559711754878535236849404328109388664845446795312989910854704312228939433256879160251993,
}
sys.set_int_max_str_digits(9999) # necessary due to our 3072 bit exponents

#print("==> os2ip:\n", os2ip(b"hello!"))
#print("==> i2osp:\n", i2osp(256, 2))
#print("==> sign:\n", rsa_pss_sign((key["N"], key["d"]), "Hello, world!"))
message = "Hello, world!"
signature = rsa_pss_sign((key["N"], key["d"]), message)
print(signature[len(signature) - 1:].hex())
print(type(signature))
RSASSA_PSS_VERIFY(key["N"], key["e"], message, signature)
