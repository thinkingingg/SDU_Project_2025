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


