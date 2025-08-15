from sm2_basic import k_leak_attack, sm2_sign, gen_keypair

def k_leak_attack(r, s, k, n):
    d_recovered = ((k - s) * pow(r + s, -1, n)) % n
    return d_recovered

if __name__ == "__main__":
    print("========== 随机数 k 泄露攻击验证 ==========")
    d, P = gen_keypair()
    msg = "Hello SM2"
    sig, k = sm2_sign(msg, d)
    r, s = sig
    recovered_d = k_leak_attack(r, s, k, 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123)
    print("恢复的私钥:", hex(recovered_d))
    print("恢复私钥是否正确:", recovered_d == d)
