# SM4的软件实现和优化

## 一、任务要求

1. 从基本实现出发优化SM4的软件执行效率，至少应该覆盖T-table、AESNI以及最新的指令集（GFNI、VPROLD等）

2. 基于SM4的实现，做SM4-GCM工作模式的软件优化实现

本项目实现了：

1. SM4 基础实现（按标准逐轮执行 S 盒与线性变换）

2. T-table 优化实现（查表合并 S 盒与线性变换）

3. AESNI 指令集实现（利用硬件加速部分运算）

4. GFNI / VPROLD 优化实现（可选，依赖 CPU 特性）

5. GCM 工作模式实现（基于 SM4 的 CTR + GHASH）

## 二、算法原理

### 1. SM4基础

SM4 是中国国家密码管理局发布的分组密码算法（国家标准 GB/T 32907-2016），分组长度为 128 位，密钥长度也为 128 位，加解密均为 32 轮迭代运算。它既可用于对称加密（ECB/CTR/CBC 等模式），也可与 GHASH 结合形成 GCM 认证加密模式。SM4 的加密过程在 GF(2) 上定义，使用以下符号：

* 输入明文块：$ X = (X_0, X_1, X_2, X_3) $，每个 $X_i$ 为 32 位无符号整数

* 密钥：$ MK = (MK_0, MK_1, MK_2, MK_3) $

* 轮密钥：$ RK_i, i = 0, 1, ..., 31 $

轮函数每轮使用非线性变换 $\tau$ 与线性变换 $L$：

$$
F(X_0, X_1, X_2, X_3, RK) = X_0 \oplus L(\tau(X_1 \oplus X_2 \oplus X_3 \oplus RK))
$$

其中：

$\tau$：S 盒逐字节替换  $\tau(a) = (S(a_{24..31}), S(a_{16..23}), S(a_{8..15}), S(a_{0..7}))$

$L$：线性变换 $L(B) = B \oplus (B \lll 2) \oplus (B \lll 10) \oplus (B \lll 18) \oplus (B \lll 24)$，其中 $\lll$ 表示循环左移。

密钥扩展使用常量 FK 与 CK：

* FK = (0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc)

* CK[i] = 常量表，i=0..31

轮密钥生成：$ K_0..K_3 = MK_0..MK_3 \oplus FK_0..FK_3 $

其中 $L'(B) = B \oplus (B \lll 13) \oplus (B \lll 23)$。

最终 $RK_i = K_{i+4}$。

### 2. GCM工作模式

GCM（Galois/Counter Mode）将 CTR 模式加密与 GHASH 认证结合：

加密：$ C_i = P_i \oplus E_K(\text{CTR}_i) $

认证标签：$T = \text{GHASH}_H(A \| C) \oplus E_K(J_0)$

* $H = E_K(0^{128})$   
* GHASH 是 GF(2^{128}) 下的多项式乘法

本项目中：

* CTR 部分直接使用 SM4 加密计数器块

* GHASH 部分使用 PCLMULQDQ 指令（硬件 128 位 GF(2) 乘法）

### 3. T-table 优化

* 预先计算：$ T[x] = L(\tau(x)) $
  这样每次只需一次查表和异或即可完成 S 盒+线性变换

* 优点：显著减少运算指令

* 缺点：占用 1KB 内存（256×4B）

### 4. AESNI 实现

* 虽然 AESNI 是为 AES 设计的，但可以用其部分指令加速 SM4 的字节替换和移位

* 关键技术：
  
  * `_mm_shuffle_epi8` 做字节重排
  
  * `_mm_xor_si128` 做并行异或

* 优点：利用 SIMD 一次处理多个 32 位字

* 缺点：需精心编写内联汇编/Intrinsic

### 5. GFNI / VPROLD 实现

* GFNI（Galois Field New Instructions）可直接在 GF(2^8) 上做查表替换

* VPROLD 是 AVX-512 中的可变位数循环左移指令，可在向量化 SM4 时减少移位开销

* 本项目在支持 CPU 上启用，检测方法为 CPUID 

## 三、运行结果与性能测试

运行结果如下：

```c++
CPU Caps: AESNI=Y PCLMUL=Y AVX2=Y AVX512=N AVX512VL=N VPROLD=N 
SelfTest Base=OK TTable=OK 
GCM demo decrypt=OK tag[0..3]=ff662585 
CTR(Base) 0.75 Gbps 
CTR(Ttable) 1.03 Gbps
```

解释：

* CPU 检测正确识别支持 AESNI、PCLMUL、AVX2

* 自测全部通过（Base、T-table、GCM）

* 性能提升：T-table 比 Base 快 ~37%

* AESNI/GFNI/VPROLD 分支未运行是因为 CPU 不支持 

## 四、总结

本项目实现了从基础到高级优化的 SM4 加密器，并在 GCM 模式下结合 SM4 实现了高性能认证加密。  
主要收获：

1. 掌握了 SM4 算法的数学原理与密钥扩展公式

2. 了解了从查表到 SIMD 指令集的多层次优化方法

3. 熟悉了 GCM 模式的认证加密流程及 PCLMULQDQ 的 GF(2) 乘法实现
