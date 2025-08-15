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

