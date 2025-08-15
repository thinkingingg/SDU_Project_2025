# SM3算法实现与优化实验

## 1. 实验概述<u></u>

本实验实现了中国商用密码算法SM3的软件实现与优化，主要包括：

1. SM3基础算法实现
2. 基于SIMD指令集的并行优化
3. 长度扩展攻击验证
4. 基于RFC6962规范的Merkle树构建与验证

## 2. 技术原理详细说明<u></u>

### 2.1 SM3算法原理详解

#### 消息填充规则（Padding）

SM3的消息填充过程确保输入消息长度是512比特(64字节)的整数倍，具体步骤如下：

设原始消息长度为$l$比特：

1. **附加比特"1"**：  
   $m \parallel 1$  
   
   - 在消息末尾添加一个"1"比特（即字节0x80）

2. **填充k个"0"比特**：  
   $m \parallel 1 \parallel 0^k$  
   
   - 填充最少$k$个"0"使得总长度满足：  
     $(l + 1 + k) \equiv 448 \mod 512$  
   - 最少填充1比特（当$l \equiv 447 \mod 512$时）

3. **附加64位长度字段**：  
   $m \parallel 1 \parallel 0^k \parallel L$  
   
   - $L$是原始消息长度$l$的64位二进制表示（大端序）
   - 最终总长度是512的整数倍

#### 压缩函数CF流程

压缩函数处理512位分组，更新8个32位状态变量$V=(A,B,C,D,E,F,G,H)$：

##### 消息扩展

1. 将512位分组划分为16个32位字$W_0,...,W_{15}$

2. 扩展生成68个32位字$W_0,...,W_{67}$：
   
   $$
   W_j = P_1(W_{j-16} \oplus W_{j-9} \oplus (W_{j-3} \lll 15)) \oplus (W_{j-13} \lll 7) \oplus W_{j-6}, \quad 16 \leq j \leq 67
   $$

3. 生成64个32位字$W'_0,...,W'_{63}$：
   
   $$
   W'_j = W_j \oplus W_{j+4}, \quad 0 \leq j \leq 63
   $$

##### 压缩主循环（64轮）

```pseudocode
OR j = 0 TO 63 DO
    // 中间变量计算
    SS1 = ((A <<< 12) + E + (T_j <<< j)) <<< 7
    SS2 = SS1 ⊕ (A <<< 12)
    TT1 = FF_j(A,B,C) + D + SS2 + W'_j
    TT2 = GG_j(E,F,G) + H + SS1 + W_j
    // 状态更新
    (D, C, B, A) = (C, B <<< 9, A, TT1)
    (H, G, F, E) = (G, F <<< 19, E, P0(TT2))

END FOR
```

#### 布尔函数数学定义

1. FF函数（0-15轮与16-63轮不同）

$$
FF_j(X,Y,Z) = 
\begin{cases} 
X \oplus Y \oplus Z & 0 \leq j \leq 15 \\
(X \land Y) \lor (X \land Z) \lor (Y \land Z) & 16 \leq j \leq 63
\end{cases}
$$

2. GG函数（0-15轮与16-63轮不同）

$$
GG_j(X,Y,Z) = 
\begin{cases} 
X \oplus Y \oplus Z & 0 \leq j \leq 15 \\
(X \land Y) \lor (\neg X \land Z) & 16 \leq j \leq 63
\end{cases}
$$

#### 置换函数详解

1. P0置换

$$
P_0(X) = X \oplus (X \lll 9) \oplus (X \lll 17)
$$

- 用于压缩函数最后一步的状态更新
2. P1置换

$$
P_1(X) = X \oplus (X \lll 15) \oplus (X \lll 23)
$$

- 专门用于消息扩展阶段

### 2.2 SIMD优化原理

#### AVX2并行处理架构

1. **数据打包**：
   
   - 使用256位YMM寄存器（`__m256i`类型）
   - 每个寄存器同时存储8个32位字（8个消息块的对应字）

2. **并行计算模式**：
   
   ```cpp
   // 示例：8个消息块的并行加法
   __m256i A = _mm256_loadu_si256((__m256i*)a_array);
   __m256i B = _mm256_loadu_si256((__m256i*)b_array);
   __m256i C = _mm256_add_epi32(A, B);
   ```

**3. 关键指令**：

| 操作类型 | 指令示例                   | 功能说明        |
| ---- | ---------------------- | ----------- |
| 算术运算 | `_mm256_add_epi32`     | 8个32位整数并行加法 |
| 逻辑运算 | `_mm256_xor_si256`     | 256位按位异或    |
| 移位操作 | `_mm256_slli_epi32`    | 8个32位整数并行左移 |
| 数据混洗 | `_mm256_shuffle_epi32` | 寄存器内数据重排列   |

#### 优化实现要点

1. **消息扩展并行化**：
   
   - 同时计算8个消息块的$W_j$和$W'_j$
   - 使用`simd_P1`函数实现并行P1置换

2. **压缩函数并行化**：
   
   - 8组状态变量$(A-H)$同步更新
   - 布尔函数FF/GG使用SIMD版本

### 2.3 Merkle树构建原理（RFC6962）

#### 哈希计算规范

1. **叶子节点哈希**：
   
   $$
   \text{LeafHash} = SM3(\texttt{0x00} \parallel \text{data})
   $$
   
   - 前缀`0x00`防止二阶原像攻击

2. **内部节点哈希**：
   
   $$
   \text{NodeHash} = SM3(\texttt{0x01} \parallel \text{left\_child} \parallel \text{right\_child})
   $$
   
   - 前缀`0x01`区分叶子节点和内部节点

#### 存在性证明验证

对于叶子节点$m_k$的证明路径$(h_1,...,h_d)$：

1. 计算当前哈希：
   
   $$
   h_0 = SM3(\texttt{0x00} \parallel m_k)
   $$

2. 按路径迭代计算：
   
   $$
   h_i = 
\begin{cases}
SM3(\texttt{0x01} \parallel h_{i-1} \parallel h_i) & \text{如果} m_k \text{是左孩子} \\
SM3(\texttt{0x01} \parallel h_i \parallel h_{i-1}) & \text{如果} m_k \text{是右孩子}
\end{cases}
   $$

3. 最终结果应与Merkle根一致

#### 数学安全性保证

- **抗碰撞性**：依赖SM3的抗碰撞特性
- **不存在性证明**：通过相邻节点的哈希值验证空缺位置
- **复杂度**：证明路径长度$O(\log n)$，验证复杂度$O(\log n)$

## 3. 实验思路<u></u>

1. **基础实现**：
   
   - 实现SM3的消息填充、压缩函数等核心组件
   - 验证标准测试向量的正确性

2. **性能优化**：
   
   - 使用AVX2指令集实现8路并行处理
   - 对比优化前后的性能差异

3. **安全分析**：
   
   - 实现长度扩展攻击验证SM3的局限性
   - 演示如何构造伪造消息

4. **应用实现**：
   
   - 基于RFC6962实现Merkle树
   - 支持10万叶子节点的大规模数据验证
   - 实现存在性/不存在性证明

## 4. 代码概述<u></u>

### 主要文件结构

SM3/  
├── sm3.h // SM3算法声明  
├── sm3.cpp // 基础实现  
├── sm3_simd.cpp // SIMD优化实现  
├── merkle_tree.h // Merkle树类定义  
└── main.cpp // 测试案例

### 关键函数

1. `sm3_hash()` - 基础SM3实现
2. `sm3_hash_simd()` - SIMD并行实现
3. `length_extension_attack()` - 长度扩展攻击
4. `MerkleTree`类 - 实现树构建和验证

## 5. 运行指南<u></u>

### 环境配置

1. **硬件要求**：
   - 支持AVX2指令集的CPU（Intel Haswell+/AMD Excavator+）
2. **软件依赖**：
   - Visual Studio 2019+ (Windows)
   - GCC 9.4+ (Linux)
   - CMake 3.12+

### 编译运行

#### Windows (Visual Studio)

```bash
msbuild SM3.sln /p:Configuration=Release
```

#### Linux

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
./SM3
```

## 6. 运行结果分析<u></u>

### 1) 基础哈希测试

> 消息：这是一个SM3哈希测试消息
> SM3哈希：b681b1b4b2fa7dc0726f95851908696cf686d1c22f49ded5fffc1283ee2f13f9

* 输出符合SM3的256位哈希特征

* 相同输入始终产生相同输出

### 2) SIMD加速测试

> 8个相同消息的哈希结果一致：
> 
> c782d84bb6322103a94c947869a54afe8287cec0cf18922caee7f1aedb6a9a79

* 验证了SIMD实现的正确性

* 实际测试中8路并行可获得约6-7倍加速比

### 3) 长度扩展攻击

> 原始哈希：c97077d65447878ad80204adf96500da3a0df11463b24f96e4cf6b37ba98cded
> 攻击后哈希：d6777bc98a874754ad9402d8da006579141f0d3a964fb263376bcfe4edcd98ba

* 成功构造出包含恶意后缀的新哈希

* 证明SM3容易受到长度扩展攻击

### 4) Merkle树测试

> 构建完成，耗时：3182 ms
> Merkle根哈希：b990d4c3c72aede4a17ddb62cc87fealb...
> 验证路径长度：17
> 验证结果：成功

* 10万叶子节点构建时间合理（约3秒）

* 验证路径长度17符合理论值（⌈log₂100000⌉=17）

* 不存在性验证正确

## 7. 结论<u></u>

1. 成功实现SM3标准算法，并通过标准测试向量验证了正确性

2. 通过引入AVX2指令集的SIMD优化，哈希计算速度得到了显著提升（理论8倍，实际6-7倍）

3. 验证了SM3对长度扩展攻击的脆弱性

4. 实现的Merkle树可有效支持大规模数据完整性验证

5. 实验结果表明RFC6962规范能有效防止二阶原像攻击
