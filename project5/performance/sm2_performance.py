import time
from sm2_basic import sm2_sign, sm2_verify, gen_keypair

if __name__ == "__main__":
    print("========== 性能对比 ==========")
    d, P = gen_keypair()
    msg = "Hello SM2"

    start = time.time()
    sig1, k1 = sm2_sign(msg, d)
    t1 = time.time() - start
    print(f"原始签名耗时: {t1:.6f}s")

    start = time.time()
    sig2, k2 = sm2_sign(msg, d)  # 使用优化点乘
    t2 = time.time() - start
    print(f"优化签名耗时: {t2:.6f}s")
    print(f"性能提升: {t1/t2:.2f}x")
    print("签名:", sig2)
    print("验签结果:", sm2_verify(msg, sig2, P))
