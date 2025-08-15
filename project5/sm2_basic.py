import hashlib
import random

# ----------------------------
# SM2 椭圆曲线参数
# ----------------------------
p  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b  = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n  = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0

# ----------------------------
# 椭圆曲线基础运算
# ----------------------------
def inverse_mod(k, p):
    if k == 0:
        raise ZeroDivisionError('division by zero')
    return pow(k, p-2, p)

def ec_add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
    if P == Q:
        lam = ((3*P[0]*P[0] + a) * inverse_mod(2*P[1], p)) % p
    else:
        lam = ((Q[1] - P[1]) * inverse_mod(Q[0] - P[0], p)) % p
    x = (lam*lam - P[0] - Q[0]) % p
    y = (lam*(P[0] - x) - P[1]) % p
    return (x, y)

def ec_double(P):
    return ec_add(P, P)

def ec_mul(k, P, w=4):
    pre = [None]*(2**w)
    pre[1] = P
    for i in range(2, 2**w):
        pre[i] = ec_add(pre[i-1], P)
    R = None
    k_bin = bin(k)[2:]
    i = 0
    while i < len(k_bin):
        if k_bin[i] == '0':
            R = ec_double(R) if R else None
            i += 1
        else:
            j = i
            val = 0
            while j < min(i+w, len(k_bin)):
                val = val*2 + int(k_bin[j])
                j += 1
            for _ in range(j - i):
                R = ec_double(R) if R else None
            R = ec_add(R, pre[val])
            i = j
    return R

def gen_keypair():
    d = random.randrange(1, n)
    P = ec_mul(d, (Gx, Gy))
    return d, P

def sm2_sign(msg, d):
    e = int(hashlib.sha256(msg.encode()).hexdigest(), 16)
    while True:
        k = random.randrange(1, n)
        x1, y1 = ec_mul(k, (Gx, Gy))
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + d, n) * (k - r*d)) % n
        if s != 0:
            break
    return (r, s), k

def sm2_verify(msg, signature, P):
    r, s = signature
    e = int(hashlib.sha256(msg.encode()).hexdigest(), 16)
    t = (r + s) % n
    if t == 0:
        return False
    x1, y1 = ec_add(ec_mul(s, (Gx, Gy)), ec_mul(t, P))
    R = (e + x1) % n
    return R == r

# ----------------------------
# 随机数 k 泄露攻击
# ----------------------------
def k_leak_attack(r, s, k):
    d_recovered = ((k - s) * inverse_mod(r + s, n)) % n
    return d_recovered
