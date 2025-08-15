# 数字水印图像泄露检测系统

## 1. 实验概述<u></u>

本项目实现了一种基于频域变换的数字水印技术，能够在宿主图像中嵌入不可见水印信息，并有效抵抗常见的图像处理攻击。系统主要包含三大功能模块：

- **水印嵌入**：将二值水印图像编码到宿主图像的频域分量中
- **水印提取**：从可能被修改的图像中恢复出水印信息
- **鲁棒性测试**：评估水印抵抗各种图像处理操作的能力

## 2. 技术原理<u></u>

### 2.1 频域水印嵌入算法

水印嵌入过程通过离散傅里叶变换(DFT)在频域实现，主要步骤如下：

1. **预处理阶段**：

$$
W_n = \frac{W - \mu_W}{\sigma_W}
$$

其中：

- $W$ 为原始水印矩阵

- $\mu_W$ 为水印均值

- $\sigma_W$ 为水印标准差
2. **频域变换与修改**：
   
   $$
   \begin{aligned}
F_I(u,v) &= \mathcal{F}\{I(x,y)\} \quad \text{(宿主图像DFT变换)} \\
M(u,v) &= \begin{cases} 
1, & \sqrt{(u-u_0)^2+(v-v_0)^2} \leq R \\
0, & \text{otherwise}
\end{cases} \quad \text{(圆形掩模)} \\
F_W(u,v) &= |F_I(u,v)| \cdot (1 + \alpha W_n \cdot M(u,v)) \quad \text{(幅度修改)} \\
I_w &= \mathcal{F}^{-1}\{F_W \cdot e^{j\phi(F_I)}\} \quad \text{(保留相位信息)}
\end{aligned}
   $$

3. **参数说明**：
   
   - $\alpha$：水印强度因子(0.05-0.3)
   - $R$：频域嵌入半径(通常为图像尺寸的1/10)

### 2.2 水印提取算法

水印提取基于频域差分原理，其数学表达式为：

$$
\hat{W}(u,v) = \frac{|\mathcal{F}\{I_w(u,v)\}| - |\mathcal{F}\{I(u,v)\}|}{\alpha \cdot |\mathcal{F}\{I(u,v)\}|} \cdot M(u,v)
$$

其中各参数定义如下：

- $\mathcal{F}\{\cdot\}$: 二维离散傅里叶变换（DFT）

- $I(u,v)$: 原始宿主图像在频域的表示

- $I_w(u,v)$: 含水印图像在频域的表示  

- $\alpha$: 水印嵌入强度因子（0 < $\alpha$ < 1）

- $M(u,v)$: 水印位置掩模矩阵，满足：
  
  $$
  M(u,v) = 
\begin{cases} 
1 & \text{在嵌入频段} \\
0 & \text{其他频段}
\end{cases}
  $$

### 2.3 算法步骤说明

1. **频域变换**：
   
   - 对原始图像和含水印图像分别进行傅里叶变换：
     
     $$
     \begin{aligned}
\mathcal{F}\{I\} &= \text{DFT}(I) \\
\mathcal{F}\{I_w\} &= \text{DFT}(I_w)
\end{aligned}
     $$

2. **幅度谱差分**：
   
   - 计算频域幅度差：
     
     $$
     \Delta(u,v) = |\mathcal{F}\{I_w\}| - |\mathcal{F}\{I\}|
     $$

3. **归一化提取**：
   
   - 通过强度因子$\alpha$归一化：
     
     $$
     \hat{W}_0(u,v) = \frac{\Delta(u,v)}{\alpha \cdot |\mathcal{F}\{I\}|}
     $$

4. **掩模过滤**：
   
   - 应用频段掩模提取有效水印：
     
     $$
     \hat{W}(u,v) = \hat{W}_0(u,v) \cdot M(u,v)
     $$

### 2.4 特性分析

- **鲁棒性**：对JPEG压缩、高斯噪声等攻击具有抵抗能力
- **不可见性**：$\alpha$控制水印可见性（建议取0.05~0.2）
- **安全性**：依赖$M(u,v)$的密钥保护

## 3. 实验设计思路<u></u>

1. **频域选择**：
   
   - 在DFT的中低频区域嵌入水印，平衡不可见性和鲁棒性
   - 使用圆形掩模控制嵌入区域

2. **鲁棒性增强**：
   
   - 多通道(RGB)独立嵌入
   - 水印信息归一化处理
   - 保留原始相位信息

3. **评估指标**：
   
   - 峰值信噪比(PSNR)评估视觉质量
   - 归一化相关系数(NCC)评估提取准确性

## 4. 代码实现概述<u></u>

### 核心类结构

```python
class DigitalWatermark:
    def __init__(self, strength=0.1, radius=30):
        """初始化水印参数"""

    def _create_circular_mask(self, shape):
        """生成圆形频域掩模"""

    def embed(self, host_img, watermark_img):
        """执行水印嵌入流程"""

    def extract(self, watermarked_img, original_img):
        """执行水印提取流程"""

    def test_robustness(self, watermarked_img, original_img, watermark_img):
        """自动化鲁棒性测试"""
```

## 5. 运行<u></u>

### 环境配置

首先安装必要的Python依赖包：

```bash
pip install numpy pillow matplotlib scipy
```

### 运行程序

运行以下命令执行程序：

```bash
python digital_watermark.py
```

程序将使用以下默认参数运行：

* 水印强度(strength): 0.1

* 嵌入半径(radius): 30

* 随机种子(seed): 12345

## 6. 运行结果<u></u>

#### 结果分析：

| 攻击类型      | 相似度  | 结果分析        |
| --------- | ---- | ----------- |
| 原始图像      | 0.27 | 基础嵌入效果      |
| 高斯噪声      | 0.10 | 对加噪敏感       |
| 裁剪10%     | 0.10 | 空间信息丢失影响显著  |
| 旋转5°      | 0.05 | 几何变换破坏严重    |
| 亮度调整+50%  | 0.09 | 非线性变换影响提取   |
| 对比度调整+50% | 0.26 | 保持相对较好的提取效果 |
| 缩放80%     | 0.27 | 尺度变化影响较小    |

#### 结论：

1. 系统对对比度调整和尺度变化具有较好鲁棒性

2. 几何变换和加噪操作会显著降低提取准确率

3. 建议后续增加几何校正模块提升性能
