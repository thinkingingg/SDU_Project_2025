#define _CRT_SECURE_NO_WARNINGS
#include <cstdint>
#include <cstring>
#include <iostream>
#include <immintrin.h>
#include <stdint.h>
#include <chrono>
#include <vector>
#include <numeric>
#include <iomanip>
#include <cstdio>
#include <string>
#include <random>

using namespace std;

/* SM3�㷨ʵ�����Ż� */

// ��ʼ����IV
const uint32_t IV[8] = {
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E
};

// ����Tj
const uint32_t T[64] = {
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x79CC4519, 0x79CC4519, 0x79CC4519, 0x79CC4519,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A,
    0x7A879D8A, 0x7A879D8A, 0x7A879D8A, 0x7A879D8A
};

/* �������ߺ��� */

// ѭ������
uint32_t rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// SIMDѭ������
__m256i simd_rotate_left(__m256i x, int n) {
    return _mm256_or_si256(_mm256_slli_epi32(x, n), _mm256_srli_epi32(x, 32 - n));
}

// ��������FF
uint32_t FF(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (x & z) | (y & z));
}

// ��������GG
uint32_t GG(uint32_t x, uint32_t y, uint32_t z, int j) {
    return (j < 16) ? (x ^ y ^ z) : ((x & y) | (~x & z));
}

// SIMD��������FF
__m256i simd_FF(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    return _mm256_or_si256(_mm256_or_si256(_mm256_and_si256(x, y),
        _mm256_and_si256(x, z)),
        _mm256_and_si256(y, z));
}

// SIMD��������GG
__m256i simd_GG(__m256i x, __m256i y, __m256i z, int j) {
    if (j < 16) return _mm256_xor_si256(_mm256_xor_si256(x, y), z);
    return _mm256_or_si256(_mm256_and_si256(x, y),
        _mm256_and_si256(_mm256_andnot_si256(x, _mm256_set1_epi32(0xFFFFFFFF)), z));
}

// �û�����P0
uint32_t P0(uint32_t x) {
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
}

// �û�����P1
uint32_t P1(uint32_t x) {
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
}

// SIMD�û�����P0
__m256i simd_P0(__m256i X) {
    __m256i x1 = _mm256_or_si256(_mm256_slli_epi32(X, 9), _mm256_srli_epi32(X, 23));
    __m256i x2 = _mm256_or_si256(_mm256_slli_epi32(X, 17), _mm256_srli_epi32(X, 15));
    return _mm256_xor_si256(X, _mm256_xor_si256(x1, x2));
}

// SIMD�û�����P1
__m256i simd_P1(__m256i X) {
    __m256i x1 = _mm256_or_si256(_mm256_slli_epi32(X, 15), _mm256_srli_epi32(X, 17));
    __m256i x2 = _mm256_or_si256(_mm256_slli_epi32(X, 23), _mm256_srli_epi32(X, 9));
    return _mm256_xor_si256(X, _mm256_xor_si256(x1, x2));
}

/* ��Ϣ������ */

// ��4�ֽ�����ת��Ϊ32λ����
uint32_t bytes_to_uint32(const uint8_t* b) {
    return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}

// ��32λ����ת��Ϊ4�ֽ�����
void uint32_to_bytes(uint32_t n, uint8_t* b) {
    b[0] = (n >> 24) & 0xFF;
    b[1] = (n >> 16) & 0xFF;
    b[2] = (n >> 8) & 0xFF;
    b[3] = n & 0xFF;
}

// ��Ϣ��亯��
vector<uint8_t> pad_message(const vector<uint8_t>& msg) {
    uint64_t bit_len = msg.size() * 8;
    vector<uint8_t> padded = msg;

    // ������λ
    padded.push_back(0x80);

    // ���0ֱ����������mod 512 = 448
    while ((padded.size() * 8 + 64) % 512 != 0) {
        padded.push_back(0x00);
    }

    // �����Ϣ����
    for (int i = 7; i >= 0; i--) {
        padded.push_back((bit_len >> (i * 8)) & 0xFF);
    }

    return padded;
}

/* SM3�����㷨 */

// ѹ������
void CF(uint32_t V[8], const uint8_t* block) {
    uint32_t W[68], W1[64];

    // ��Ϣ��չ
    for (int i = 0; i < 16; i++) {
        W[i] = bytes_to_uint32(block + i * 4);
    }
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ rotate_left(W[i - 3], 15))
            ^ rotate_left(W[i - 13], 7) ^ W[i - 6];
    }
    for (int i = 0; i < 64; i++) {
        W1[i] = W[i] ^ W[i + 4];
    }

    // ѹ��������ѭ��
    uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
    uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = rotate_left(rotate_left(A, 12) + E + rotate_left(T[j], j), 7);
        uint32_t SS2 = SS1 ^ rotate_left(A, 12);
        uint32_t TT1 = FF(A, B, C, j) + D + SS2 + W1[j];
        uint32_t TT2 = GG(E, F, G, j) + H + SS1 + W[j];

        D = C;
        C = rotate_left(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = rotate_left(F, 19);
        F = E;
        E = P0(TT2);
    }

    // ��������
    V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
    V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
}

// SIMDѹ������(8����Ϣ�鲢�д���)
void simd_CF(__m256i V[8], const uint8_t* blocks) {
    __m256i W[68], W1[64];

    // ��Ϣ��չ
    for (int i = 0; i < 16; i++) {
        uint32_t temp[8];
        for (int j = 0; j < 8; j++) {
            temp[j] = bytes_to_uint32(blocks + j * 64 + i * 4);
        }
        W[i] = _mm256_loadu_si256((__m256i*)temp);
    }

    for (int i = 16; i < 68; i++) {
        __m256i temp = _mm256_xor_si256(
            _mm256_xor_si256(W[i - 16], W[i - 9]),
            simd_rotate_left(W[i - 3], 15));
        W[i] = _mm256_xor_si256(
            _mm256_xor_si256(simd_P1(temp), simd_rotate_left(W[i - 13], 7)),
            W[i - 6]);
    }

    for (int i = 0; i < 64; i++) {
        W1[i] = _mm256_xor_si256(W[i], W[i + 4]);
    }

    // ��ʼ���Ĵ���
    __m256i A = V[0], B = V[1], C = V[2], D = V[3];
    __m256i E = V[4], F = V[5], G = V[6], H = V[7];

    for (int j = 0; j < 64; j++) {
        __m256i SS1 = simd_rotate_left(
            _mm256_add_epi32(
                _mm256_add_epi32(simd_rotate_left(A, 12), E),
                simd_rotate_left(_mm256_set1_epi32(T[j]), j)), 7);

        __m256i SS2 = _mm256_xor_si256(SS1, simd_rotate_left(A, 12));
        __m256i TT1 = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_add_epi32(simd_FF(A, B, C, j), D),
                SS2), W1[j]);

        __m256i TT2 = _mm256_add_epi32(
            _mm256_add_epi32(
                _mm256_add_epi32(simd_GG(E, F, G, j), H),
                SS1), W[j]);

        D = C;
        C = simd_rotate_left(B, 9);
        B = A;
        A = TT1;

        H = G;
        G = simd_rotate_left(F, 19);
        F = E;
        E = simd_P0(TT2);
    }

    // ��������
    V[0] = _mm256_xor_si256(V[0], A);
    V[1] = _mm256_xor_si256(V[1], B);
    V[2] = _mm256_xor_si256(V[2], C);
    V[3] = _mm256_xor_si256(V[3], D);
    V[4] = _mm256_xor_si256(V[4], E);
    V[5] = _mm256_xor_si256(V[5], F);
    V[6] = _mm256_xor_si256(V[6], G);
    V[7] = _mm256_xor_si256(V[7], H);
}

/* SM3��ϣ���� */

// ����SM3��ϣ����
void sm3_hash(const vector<uint8_t>& message, vector<uint8_t>& hash) {
    vector<uint8_t> padded = pad_message(message);
    uint32_t V[8];
    memcpy(V, IV, sizeof(V));

    size_t blocks = padded.size() / 64;
    for (size_t i = 0; i < blocks; i++) {
        CF(V, &padded[i * 64]);
    }

    hash.resize(32);
    for (int i = 0; i < 8; i++) {
        uint32_to_bytes(V[i], &hash[i * 4]);
    }
}

// SIMD���ٵ�SM3��ϣ����(8����Ϣ���д���)
void sm3_hash_simd(const vector<vector<uint8_t>>& messages, vector<vector<uint8_t>>& hashes) {
    if (messages.size() != 8) {
        throw runtime_error("SIMD�汾��Ҫ����8����Ϣ");
    }

    // ׼��8����Ϣ��
    vector<uint8_t> blocks(8 * 64);
    for (int i = 0; i < 8; i++) {
        if (messages[i].size() != 64) {
            throw runtime_error("ÿ����Ϣ��������64�ֽ�");
        }
        memcpy(&blocks[i * 64], messages[i].data(), 64);
    }

    // ��ʼ��8��IV
    __m256i V[8];
    for (int i = 0; i < 8; i++) {
        uint32_t tmp[8];
        for (int j = 0; j < 8; j++) tmp[j] = IV[i];
        V[i] = _mm256_loadu_si256((__m256i*)tmp);
    }

    // ִ��ѹ������
    simd_CF(V, blocks.data());

    // ��ȡ���
    hashes.resize(8, vector<uint8_t>(32));
    for (int i = 0; i < 8; i++) {
        uint32_t buffer[8];
        _mm256_storeu_si256((__m256i*)buffer, V[i]);
        for (int j = 0; j < 8; j++) {
            uint32_to_bytes(buffer[j], &hashes[j][i * 4]);
        }
    }
}

/* ������չ���� */

// ������չ��������
void length_extension_attack(const uint32_t intermediate_hash[8],
    const vector<uint8_t>& suffix,
    uint64_t original_length_bits,
    vector<uint8_t>& new_hash) {
    uint32_t V[8];
    memcpy(V, intermediate_hash, sizeof(V));

    // ���칥����Ϣ: ��׺+���+ԭʼ����
    vector<uint8_t> attack_msg = suffix;
    attack_msg.push_back(0x80);

    uint64_t total_bits = original_length_bits + attack_msg.size() * 8;
    while ((total_bits + 64) % 512 != 0) {
        attack_msg.push_back(0x00);
        total_bits += 8;
    }

    // ���ԭʼ����
    for (int i = 7; i >= 0; i--) {
        attack_msg.push_back((total_bits >> (i * 8)) & 0xFF);
    }

    // �����¹�ϣ
    size_t blocks = attack_msg.size() / 64;
    for (size_t i = 0; i < blocks; i++) {
        CF(V, &attack_msg[i * 64]);
    }

    new_hash.resize(32);
    for (int i = 0; i < 8; i++) {
        uint32_to_bytes(V[i], &new_hash[i * 4]);
    }
}

/* Merkle��ʵ�� */

class MerkleTree {
private:
    vector<vector<vector<uint8_t>>> tree;  // ���ĸ���

    // ����Ҷ�ӽڵ��ϣ(RFC6962)
    vector<uint8_t> hash_leaf(const vector<uint8_t>& data) {
        vector<uint8_t> input = { 0x00 };
        input.insert(input.end(), data.begin(), data.end());
        vector<uint8_t> hash;
        sm3_hash(input, hash);
        return hash;
    }

    // �����ڲ��ڵ��ϣ(RFC6962)
    vector<uint8_t> hash_node(const vector<uint8_t>& left, const vector<uint8_t>& right) {
        vector<uint8_t> input = { 0x01 };
        input.insert(input.end(), left.begin(), left.end());
        input.insert(input.end(), right.begin(), right.end());
        vector<uint8_t> hash;
        sm3_hash(input, hash);
        return hash;
    }

public:
    // ���캯������Ҷ�ӽڵ㹹��Merkle��
    MerkleTree(const vector<vector<uint8_t>>& leaves) {
        if (leaves.empty()) return;

        // ��һ��: Ҷ�ӽڵ�
        vector<vector<uint8_t>> current_level;
        for (const auto& leaf : leaves) {
            current_level.push_back(hash_leaf(leaf));
        }
        tree.push_back(current_level);

        // �����ϲ�ڵ�
        while (current_level.size() > 1) {
            vector<vector<uint8_t>> next_level;

            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    next_level.push_back(hash_node(current_level[i], current_level[i + 1]));
                }
                else {
                    next_level.push_back(current_level[i]);  // �������ڵ�ʱ�������һ��
                }
            }

            tree.push_back(next_level);
            current_level = next_level;
        }
    }

    // ��ȡMerkle��
    vector<uint8_t> get_root() const {
        if (tree.empty()) return {};
        return tree.back()[0];
    }

    // ��ȡ������֤��·��
    vector<vector<uint8_t>> get_inclusion_proof(size_t leaf_index) const {
        vector<vector<uint8_t>> proof;

        if (tree.empty() || leaf_index >= tree[0].size()) {
            return proof;
        }

        size_t idx = leaf_index;
        for (size_t level = 0; level < tree.size() - 1; level++) {
            size_t sibling = (idx % 2 == 0) ? idx + 1 : idx - 1;
            if (sibling < tree[level].size()) {
                proof.push_back(tree[level][sibling]);
            }
            idx /= 2;
        }

        return proof;
    }

    // ��֤������֤��
    static bool verify_inclusion(const vector<uint8_t>& leaf_data,
        const vector<uint8_t>& root_hash,
        const vector<vector<uint8_t>>& proof,
        size_t leaf_index) {
        vector<uint8_t> current_hash = { 0x00 };
        current_hash.insert(current_hash.end(), leaf_data.begin(), leaf_data.end());
        vector<uint8_t> hash;
        sm3_hash(current_hash, hash);

        size_t idx = leaf_index;
        for (const auto& sibling : proof) {
            vector<uint8_t> parent_input = { 0x01 };

            if (idx % 2 == 0) {
                parent_input.insert(parent_input.end(), hash.begin(), hash.end());
                parent_input.insert(parent_input.end(), sibling.begin(), sibling.end());
            }
            else {
                parent_input.insert(parent_input.end(), sibling.begin(), sibling.end());
                parent_input.insert(parent_input.end(), hash.begin(), hash.end());
            }

            sm3_hash(parent_input, hash);
            idx /= 2;
        }

        return hash == root_hash;
    }
};

/* ���Ժ��� */

// ���Ի���SM3��ϣ
void test_basic_hash() {
    string message = "����һ��SM3��ϣ������Ϣ";
    vector<uint8_t> msg(message.begin(), message.end());
    vector<uint8_t> hash;

    sm3_hash(msg, hash);

    cout << "��Ϣ: " << message << endl;
    cout << "SM3��ϣ: ";
    for (uint8_t byte : hash) printf("%02x", byte);
    cout << endl;
}

// ����SIMD����
void test_simd_acceleration() {
    vector<vector<uint8_t>> messages(8, vector<uint8_t>(64, 'a'));
    vector<vector<uint8_t>> hashes;

    sm3_hash_simd(messages, hashes);

    cout << "SIMD���ٲ���(8����ͬ��Ϣ):" << endl;
    for (int i = 0; i < 8; i++) {
        cout << "��ϣ " << i << ": ";
        for (uint8_t byte : hashes[i]) printf("%02x", byte);
        cout << endl;
    }
}

// ���Գ�����չ����
void test_length_extension_attack() {
    string original_msg = "ԭʼ��Ϣ";
    vector<uint8_t> original(original_msg.begin(), original_msg.end());
    vector<uint8_t> original_hash;
    sm3_hash(original, original_hash);

    string malicious_suffix = "�����׺";
    vector<uint8_t> suffix(malicious_suffix.begin(), malicious_suffix.end());

    vector<uint8_t> new_hash;
    length_extension_attack((uint32_t*)original_hash.data(), suffix, original.size() * 8, new_hash);

    cout << "\n������չ��������:" << endl;
    cout << "ԭʼ��Ϣ: " << original_msg << endl;
    cout << "ԭʼ��ϣ: ";
    for (uint8_t byte : original_hash) printf("%02x", byte);
    cout << "\n�����׺: " << malicious_suffix << endl;
    cout << "�������ϣ: ";
    for (uint8_t byte : new_hash) printf("%02x", byte);
    cout << endl;
}

// ����Merkle��(10���Ҷ�ӽڵ�)
void test_merkle_tree() {
    const int NUM_LEAVES = 100000;
    vector<vector<uint8_t>> leaves;

    cout << "\n����Merkle��(10���Ҷ�ӽڵ�)..." << endl;

    // ����10������Ҷ�ӽڵ�
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < NUM_LEAVES; i++) {
        vector<uint8_t> leaf(32);  // ÿ��Ҷ��32�ֽ�
        for (auto& byte : leaf) {
            byte = dis(gen);
        }
        leaves.push_back(leaf);
    }

    // ����Merkle��
    auto start = chrono::high_resolution_clock::now();
    MerkleTree tree(leaves);
    auto end = chrono::high_resolution_clock::now();

    auto duration = chrono::duration_cast<chrono::milliseconds>(end - start);
    cout << "������ɣ���ʱ: " << duration.count() << " ms" << endl;

    // ��ȡMerkle��
    auto root = tree.get_root();
    cout << "Merkle����ϣ: ";
    for (uint8_t byte : root) printf("%02x", byte);
    cout << endl;

    // ���԰�����֤��
    size_t test_index = 12345;  // ���Ե�12345��Ҷ��
    auto proof = tree.get_inclusion_proof(test_index);

    cout << "\n������֤������(Ҷ��" << test_index << "):" << endl;
    cout << "֤��·������: " << proof.size() << endl;

    bool verified = MerkleTree::verify_inclusion(leaves[test_index], root, proof, test_index);
    cout << "��֤���: " << (verified ? "�ɹ�" : "ʧ��") << endl;

    // ���Բ����ڵ�Ҷ��
    vector<uint8_t> non_existent_leaf(32, 0xFF);
    bool non_existent_verified = MerkleTree::verify_inclusion(non_existent_leaf, root, proof, test_index);
    cout << "������Ҷ����֤: " << (non_existent_verified ? "�������" : "��ȷ�ܾ�") << endl;
}

int main() {
    test_basic_hash();
    test_simd_acceleration();
    test_length_extension_attack();
    test_merkle_tree();
    return 0;
}

