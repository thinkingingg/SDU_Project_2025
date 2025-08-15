import numpy as np
from PIL import Image, ImageDraw, ImageFont
import matplotlib.pyplot as plt
from scipy.fft import fft2, ifft2, fftshift, ifftshift


class DigitalWatermark:
    def __init__(self, strength=0.1, radius=30):
        """
        初始化水印系统
        :param strength: 水印强度 (0-1)
        :param radius: 水印嵌入的频域半径
        """
        self.strength = strength
        self.radius = radius

    def _create_circular_mask(self, shape):
        """创建圆形掩模用于频域水印嵌入"""
        h, w = shape
        center = (h // 2, w // 2)
        y, x = np.ogrid[:h, :w]
        mask = (x - center[1]) ** 2 + (y - center[0]) ** 2 <= self.radius ** 2
        return mask

    def embed(self, host_img, watermark_img):
        """
        嵌入水印
        :param host_img: PIL Image对象 (宿主图像)
        :param watermark_img: PIL Image对象 (水印图像，灰度)
        :return: 含水印的PIL Image
        """
        # 转换图像为numpy数组
        host_arr = np.array(host_img)
        watermark_arr = np.array(watermark_img.resize(host_img.size))

        # 归一化水印图像
        watermark_norm = (watermark_arr - watermark_arr.mean()) / watermark_arr.std()

        # 对每个通道嵌入水印
        watermarked = host_arr.copy().astype(np.float32)
        for c in range(3):
            channel = host_arr[:, :, c]

            # 傅里叶变换
            f = fft2(channel)
            fshift = fftshift(f)

            # 创建频域掩模
            mask = self._create_circular_mask(channel.shape)

            # 嵌入水印
            phase = np.angle(fshift)
            magnitude = np.abs(fshift)
            magnitude[mask] += self.strength * watermark_norm[mask] * magnitude[mask]

            # 重建频域信号
            watermarked_shift = magnitude * np.exp(1j * phase)
            watermarked_f = ifftshift(watermarked_shift)
            watermarked_channel = np.real(ifft2(watermarked_f))

            # 归一化并存储
            watermarked[:, :, c] = np.clip(watermarked_channel, 0, 255)

        return Image.fromarray(watermarked.astype(np.uint8))

    def extract(self, watermarked_img, original_img):
        """
        提取水印
        :param watermarked_img: PIL Image (含水印图像)
        :param original_img: PIL Image (原始图像)
        :return: 提取的水印图像 (PIL Image)
        """
        # 转换图像为numpy数组
        wm_arr = np.array(watermarked_img)
        org_arr = np.array(original_img)

        # 初始化提取的水印
        extracted = np.zeros(wm_arr.shape[:2])

        for c in range(3):
            # 计算两幅图像的频域差异
            f_wm = fftshift(fft2(wm_arr[:, :, c]))
            f_org = fftshift(fft2(org_arr[:, :, c]))

            # 提取水印信息
            magnitude_wm = np.abs(f_wm)
            magnitude_org = np.abs(f_org)

            # 创建频域掩模
            mask = self._create_circular_mask(wm_arr.shape[:2])

            # 计算水印
            delta = (magnitude_wm - magnitude_org) / (self.strength * magnitude_org + 1e-10)
            extracted += delta * mask

        # 平均三个通道的结果
        extracted = extracted / 3

        # 归一化并缩放
        extracted = (extracted - extracted.min()) / (extracted.max() - extracted.min()) * 255

        return Image.fromarray(extracted.astype(np.uint8))

    def test_robustness(self, watermarked_img, original_img, watermark_img):
        """测试水印的鲁棒性"""

        # 定义攻击函数
        def add_noise(img, var=0.01):
            arr = np.array(img) / 255.0
            noise = np.random.normal(0, var ** 0.5, arr.shape)
            noisy = np.clip(arr + noise, 0, 1) * 255
            return Image.fromarray(noisy.astype(np.uint8))

        def crop(img, ratio=0.1):
            w, h = img.size
            box = (w * ratio, h * ratio, w * (1 - ratio), h * (1 - ratio))
            cropped = img.crop(box)
            return cropped.resize(img.size)

        def rotate(img, angle=5):
            return img.rotate(angle).resize(img.size)

        def adjust_brightness(img, factor=1.5):
            arr = np.array(img) * factor
            return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))

        def adjust_contrast(img, factor=1.5):
            arr = np.array(img).astype(np.float32)
            mean = arr.mean()
            adjusted = mean + (arr - mean) * factor
            return Image.fromarray(np.clip(adjusted, 0, 255).astype(np.uint8))

        def scale(img, factor=0.8):
            w, h = img.size
            scaled = img.resize((int(w * factor), int(h * factor)))
            return scaled.resize(img.size)

        # 定义攻击列表
        attacks = [
            ("Original", lambda x: x),
            ("Gaussian Noise", lambda x: add_noise(x, 0.02)),
            ("Cropping 10%", lambda x: crop(x, 0.1)),
            ("Rotation 5°", lambda x: rotate(x, 5)),
            ("Brightness +50%", lambda x: adjust_brightness(x, 1.5)),
            ("Contrast +50%", lambda x: adjust_contrast(x, 1.5)),
            ("Scaling 80%", lambda x: scale(x, 0.8))
        ]

        # 准备绘图
        plt.figure(figsize=(15, 10))

        for i, (name, attack_fn) in enumerate(attacks):
            # 应用攻击
            attacked_img = attack_fn(watermarked_img)

            # 提取水印
            extracted = self.extract(attacked_img, original_img)

            # 计算相似度
            orig_wm = np.array(watermark_img.resize(extracted.size))
            ext_wm = np.array(extracted)
            similarity = np.corrcoef(orig_wm.flatten(), ext_wm.flatten())[0, 1]

            # 绘制结果
            plt.subplot(3, 4, i + 1)
            plt.imshow(attacked_img)
            plt.title(f"{name}\nSimilarity: {similarity:.2f}")
            plt.axis('off')

            plt.subplot(3, 4, i + 5)
            plt.imshow(extracted, cmap='gray')
            plt.title("Extracted Watermark")
            plt.axis('off')

        plt.tight_layout()
        plt.show()


# 示例使用
if __name__ == "__main__":
    # 1. 创建示例图像和水印
    img_size = (512, 512)
    watermark_size = (128, 128)

    # 创建宿主图像
    host_img = Image.new('RGB', img_size, color=(70, 130, 180))
    draw = ImageDraw.Draw(host_img)
    try:
        font = ImageFont.truetype("arial.ttf", 40)
    except:
        font = ImageFont.load_default()
    draw.text((150, 220), "Sample Image", fill=(255, 255, 255), font=font)

    # 创建水印图像
    watermark_img = Image.new('L', watermark_size, color=0)
    draw = ImageDraw.Draw(watermark_img)
    try:
        font = ImageFont.truetype("arial.ttf", 20)
    except:
        font = ImageFont.load_default()
    draw.text((10, 50), "WATERMARK", fill=255, font=font)

    # 2. 初始化水印系统
    dw = DigitalWatermark(strength=0.2, radius=40)

    # 3. 嵌入水印
    watermarked_img = dw.embed(host_img, watermark_img)

    # 4. 提取水印
    extracted_watermark = dw.extract(watermarked_img, host_img)

    # 5. 显示结果
    plt.figure(figsize=(12, 6))

    plt.subplot(2, 3, 1)
    plt.imshow(host_img)
    plt.title("Original Image")
    plt.axis('off')

    plt.subplot(2, 3, 2)
    plt.imshow(watermark_img, cmap='gray')
    plt.title("Watermark Image")
    plt.axis('off')

    plt.subplot(2, 3, 3)
    plt.imshow(watermarked_img)
    plt.title("Watermarked Image")
    plt.axis('off')

    plt.subplot(2, 3, 4)
    plt.imshow(extracted_watermark, cmap='gray')
    plt.title("Extracted Watermark")
    plt.axis('off')

    # 计算PSNR
    mse = np.mean((np.array(host_img) - np.array(watermarked_img)) ** 2)
    psnr = 10 * np.log10(255 ** 2 / mse) if mse != 0 else float('inf')

    plt.subplot(2, 3, 5)
    diff = np.array(watermarked_img) - np.array(host_img)
    plt.imshow(np.clip(diff + 128, 0, 255).astype(np.uint8))
    plt.title(f"Difference (PSNR: {psnr:.2f} dB)")
    plt.axis('off')

    plt.tight_layout()
    plt.show()

    # 6. 测试鲁棒性
    dw.test_robustness(watermarked_img, host_img, watermark_img)