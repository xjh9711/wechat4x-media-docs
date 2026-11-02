# wechat4x-media-docs

微信 Windows 4.x（4.1.x，`xwechat_files` 布局）本地**图片与文档附件解析**模块。
纯 Python 标准库（图片解码用到 Pillow），只读本地文件，不碰微信进程、不做内存注入。

## 已逆向的格式事实

- **消息表名** = `Msg_` + `md5(chatroom username)`（`message/message_0.db`）
- **local_type 是复合整数**：`(子类型 << 32) | 基础类型`
  - base：`3`=图片 `34`=语音 `43`=视频 `47`=表情 `42`=名片 `49`=appmsg
  - appmsg **子类型 6 = 文件消息**，例：`(6<<32)|49 = 25769803825`
- **文档附件**：按**原始文件名**明文落盘在 `msg/file/<年-月>/`，重名加 `(n)`；
  docx 可用 zipfile+XML 提全量文本（无第三方依赖），pdf/pptx/xlsx 为明文容器
- **图片**：`msg/attach/<md5(chatroom)>/<年-月>/Img/<内容md5>.dat`，变体
  `_t`=缩略、`_h`=HD。`.dat` 结构（部分样本）：

  ```
  [0-30]    固定壳：magic 07 08 56 32 + 版本 + 长度
  [15-30]   16B 图片组指纹（同一原图的 HD/mid 变体共享）
  [3072+]   明文 EXIF（真实宽高在 tag 0x100/0x101）
  [...]     JPEG 头 —— SOF0 宽高被故意改小（如 7728×5152 改成 170×256）
  [...]     JPEG 熵编码主体（明文）
  ```

## 能力矩阵（5 群 3.7 万条消息实测）

| 类型 | 可解析 | 方法 |
|---|---|---|
| docx | 26/26 | `docx_text()`：zipfile + word/document.xml → 全量文本 |
| pdf | 23/23 | `%PDF` 头验证 + 任意 PDF 文本工具 |
| png/jpg | 7/7 | PIL 直接解码（含 1080×9588 长图） |
| 图片 .dat | 部分 | `plaintext` / `size_spoofed`（重建尺寸后可解）/ `encrypted`（未解） |
| 明文缩略图 | 43+ | `cache/<月>/Message/<md5(chatroom)>/Thumb/`，时间戳≠发送时间 |

## 未解决：本地图片加密

大多数群聊落盘图片为**整文件 AES 加密**。已实测排除的密钥来源：
消息 XML 内 `aeskey`（直接 + 8 种派生）、数据库 key、进程内存 3.2 万 hex
候选、Config.Cipher blob 二进制滑窗候选。本地密钥另有存储位置（2026-11 时点
未定位）。**不要再用单字节 XOR 思路——那是 3.x，4.x 不是。**

## 用法

```python
import sys; sys.path.insert(0, "path/to/repo")
from windows_media_docs import (
    chatroom_md5, msg_table, is_appmsg_file,        # 映射层
    parse_file_msg, match_files_on_disk, docx_text, # 文档层
    probe_dat, extract_plaintext_jpg,               # 图片层
    rebuild_spoofed_jpg, decode_dat_image,          # 图片层(重建)
    collect_thumb_cache,                            # 缩略图缓存
)

table = msg_table("12345678@chatroom")              # → "Msg_<md5>"
text = docx_text(r"<wxid>\msg\file\2026-10\报告.docx")
probe = probe_dat(open(dat_path, "rb").read(200_000))
if probe.kind == "size_spoofed":
    im = decode_dat_image(dat_path)                 # PIL Image（尾部可能有洞）
```

自测：`python windows_media_docs.py`（输出 `self-test ok`）。

## 隐私边界

- 模块与文档**不含**任何真实群 ID、wxid、账号数据（自测用合成值）。
- 图片/文档含聊天成员个人内容（人像、证件、住址），导出与发布前确认用途与授权。
- `_h.dat` 可能是数千万像素相机原图，输出前先缩放。

## License

MIT
