import random
import hashlib
from sm2_basic import ec_add, ec_mul, Gx, Gy, n, sm2_verify, gen_keypair

def forge_sm2_signature_experiment(P):
    r_forged = random.randrange(1, n)
    s_forged = random.randrange(1, n)
    t = (r_forged + s_forged) % n
    x1, y1 = ec_add(ec_mul(s_forged, (Gx, Gy)), ec_mul(t, P))
    e_forged = (r_forged - x1) % n
    msg = "中本聪伪造签名实验消息"
    return msg, (r_forged, s_forged), e_forged

def vulnerable_verify(P, signature, e_forged):
    r, s = signature
    t = (r + s) % n
    x1, y1 = ec_add(ec_mul(s, (Gx, Gy)), ec_mul(t, P))
    R_check = (e_forged + x1) % n
    return R_check == r

if __name__ == "__main__":
    print("========== 数字签名伪造演示 ==========")
    d, P = gen_keypair()
    forged_msg, forged_sig, forged_e = forge_sm2_signature_experiment(P)
    print("伪造消息:", forged_msg)
    print("伪造签名:", forged_sig)
    print("脆弱验证结果 (应通过):", vulnerable_verify(P, forged_sig, forged_e))
    real_e = int(hashlib.sha256(forged_msg.encode()).hexdigest(), 16)
    print("安全验证结果 (应失败):", sm2_verify(forged_msg, forged_sig, P))
