circom实现poseidon2哈希算法的电路
====================

## 一、任务要求

1) poseidon2哈希算法参数参考参考文档1的Table1，用(n,t,d)=(256,3,5)或(256,2,5)
2) 电路的公开输入用poseidon2哈希值，隐私输入为哈希原象，哈希算法的输入只考虑一个block即可。
3) 用Groth16算法生成证明

## 二、 算法原理

### 1. Poseidon哈希算法

Poseidon 系列哈希函数是一类基于代数置换（algebraic permutation）的 sponge 结构哈希算法，其特点是：

* 高度友好于 zk-SNARKs/zk-STARKs 电路实现（低约束数）。

* 用有限域上的线性层（MDS 矩阵变换） 和 非线性 S-box交替迭代。

Poseidon2 是 Poseidon 的优化版本，采用更少的全轮数（full rounds），更多的部分轮数（partial rounds），从而减少电路规模。

### 2. 轮操作

Poseidon2 使用如下轮结构：

1. **全轮（Full Round）**：
   
   * 所有 state 分量都经过 S-box。

2. **部分轮（Partial Round）**：
   
   * 仅对一个固定分量（通常是最后一个）经过 S-box，其余分量直接传递。

轮常数与 MDS 矩阵的设计保证了置换的密码安全性。 

### 3. S-box 指数

本任务中：d=5

对应计算：$x^5 = (x^2)^2 \cdot x$

这样可以在电路中减少乘法门数量（共 3 次乘法完成指数计算）。

### 4. Sponge 模式

输入哈希数据时：

* 初始化 state：$s_0 = 0, \quad s_1 = \text{消息}, \quad s_2 = 0$

* 经过一次 permutation 。

* 输出 digest：$\text{digest} = s_0^{\text{(out)}}$

## 三、实现思路

### 1. Circom 电路设计

实现思路分为两层：

1. Poseidon2Core（核心置换电路）
   
   * 固定参数：$t = 3, R_F = 8, R_P = 56, d = 5$。
   
   * 内置：
     
     * ROUND_CONSTANTS：预生成的轮常数表。
     
     * MDS 矩阵：用扁平数组存储，节省内存。
     
     * applyMDS 函数：实现矩阵与向量相乘。
     
     * pow5 函数：高效实现 。

2. Poseidon2HasherTop（哈希顶层）
   
   * 输入：私有 preimage。
   
   * 输出：公开 digest。
   
   * 结构：初始化 state → 调用 Poseidon2Core → 输出 state[0]。 

### 2. Groth16 证明生成

生成证明流程：

1. **编译电路**：
   
   ```circom
   circom poseidon2.circom --r1cs --wasm --sym
   ```

2. **生成 proving key & verifying key**：
   
   ```circom
   snarkjs groth16 setup poseidon2.r1cs powersOfTau.ptau poseidon2.zkey
   ```

3. **生成证明**：
   
   ```circom
   snarkjs groth16 prove poseidon2.zkey witness.wtns proof.json public.json   
   ```

4. **验证证明**：
   
   ```circom
   snarkjs groth16 verify verification_key.json public.json proof.json
   ```

## 四、优化与安全性

### 1. 优化

1. 轮常数与 MDS 矩阵固定：避免运行时生成，减少电路约束。

2. S-box 优化：指数运算展开为平方和乘法，减少乘法门。

3. 部分轮减少复杂度：仅单分量经过非线性变换，显著降低约束数。

4. 单 block 模式：避免 padding 与多 block 处理，结构更简洁。 

### 2. 数学安全性

* **抗碰撞性**：源自 MDS 矩阵的扩散性 + S-box 的非线性。

* **抗差分性**：部分轮保证了信息在多轮中充分扩散，防止差分攻击。

* **零知识友好性**：乘法门数较低，适合电路证明。

## 五、总结

该实现基于 Poseidon2 参数集 ，构造了一个仅处理单 block 的哈希电路，适配 Groth16 证明系统。通过优化 S-box 实现与固定常量，电路约束数可控，同时保持密码学安全性。
