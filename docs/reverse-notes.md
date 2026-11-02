## 图片 .dat 逆向记录（2026-11-02）

4.1.15.56 xwechat_files 实测：图片 .dat 不再是 3.x 的单字节 XOR。头部 31B 固定壳（magic `07 08 56 32`）+ 16B 图片组指纹（同原图的 HD/mid 变体共享）+ 明文 EXIF（真实宽高 tag 0x100/0x101）+ SOF0 宽高被改小的伪装 JPEG 头 + 明文熵编码主体。部分样本（如相机原图直传）主体明文，可用 EXIF 尺寸重建 SOF0 后以 `LOAD_TRUNCATED_IMAGES` 解码，主体完整、尾部偶有加密洞。其余大多数（含 10-11 月群聊全部落盘文件）整文件 AES 加密：消息 XML `aeskey`（含 8 种派生）、db key、进程内 3.2 万 hex 候选、Config blob 二进制滑窗候选全部排除，本地密钥另有存储位置，2026-11 时点无解。实现见 `scripts/windows_media_docs.py`。
