from dataclasses import dataclass
from typing import List, Tuple, Set, Dict, Any
from functools import reduce
import secrets
import hashlib
from phe import paillier

# 定义安全参数
PRIME_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
PRIME = int(PRIME_HEX, 16)
SUBGROUP_ORDER = (PRIME - 1) // 2
GENERATOR = 2


def hash_to_group(element: bytes) -> int:
    """将元素哈希映射到乘法子群"""
    digest = hashlib.sha3_256(element).digest()
    return pow(int.from_bytes(digest, "big"), 2, PRIME)


class ProtocolInitiator:
    """协议发起方，持有数据集V"""

    def __init__(self, dataset: List[bytes]):
        self.dataset = dataset
        self.private_exponent = secrets.randbelow(SUBGROUP_ORDER - 1) + 1
        self.processed_data = [pow(hash_to_group(item), self.private_exponent, PRIME)
                               for item in self.dataset]

    def first_phase(self) -> List[int]:
        """第一阶段：发送处理后的数据"""
        return sorted(self.processed_data, key=lambda _: secrets.randbits(128))

    def third_phase(self, received_pairs: List[Tuple[int, paillier.EncryptedNumber]],
                    verification_set: Set[int],
                    public_key: paillier.PaillierPublicKey) -> paillier.EncryptedNumber:
        """第三阶段：计算交集和"""
        sum_cipher = public_key.encrypt(0)
        for point, cipher in received_pairs:
            shared_point = pow(point, self.private_exponent, PRIME)
            if shared_point in verification_set:
                sum_cipher += cipher
        return sum_cipher + public_key.encrypt(0)  # 随机化

class ProtocolResponder:
    """协议响应方，持有键值对W"""

    def __init__(self, items: List[Tuple[bytes, int]]):
        self.items = items
        self.private_exponent = secrets.randbelow(SUBGROUP_ORDER - 1) + 1
        self.public_key, self.private_key = paillier.generate_paillier_keypair()

    def second_phase(self, received_points: List[int]) -> Tuple[List[int], List[Tuple[int, paillier.EncryptedNumber]]]:
        """第二阶段：验证集合和加密数据"""
        verification_set = [pow(point, self.private_exponent, PRIME) for point in received_points]
        encrypted_items = [
            (pow(hash_to_group(key), self.private_exponent, PRIME),
             self.public_key.encrypt(value))
            for key, value in self.items
        ]
        return (sorted(verification_set, key=lambda _: secrets.randbits(128)),
                sorted(encrypted_items, key=lambda _: secrets.randbits(128)))

    def decrypt_result(self, ciphertext: paillier.EncryptedNumber) -> int:
        """解密最终结果"""
        return self.private_key.decrypt(ciphertext)


def execute_protocol():
    # 测试数据
    initiator_data = [name.encode("utf-8") for name in ["张三", "李四", "王五"]]
    responder_data = [(name.encode("utf-8"), score) for name, score in [("李四", 25), ("赵六", 20), ("张三", 50)]]

    # 协议执行
    party1 = ProtocolInitiator(initiator_data)
    party2 = ProtocolResponder(responder_data)

    phase1_result = party1.first_phase()
    phase2_verification, phase2_pairs = party2.second_phase(phase1_result)

    final_cipher = party1.third_phase(phase2_pairs, set(phase2_verification), party2.public_key)
    intersection_sum = party2.decrypt_result(final_cipher)

    print(f"交集元素关联值总和: {intersection_sum}")


if __name__ == "__main__":
    execute_protocol()
