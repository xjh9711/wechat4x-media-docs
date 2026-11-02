"""Windows 微信 4.x 本地图片与文档解析。

来源: 2026-11-02 对微信 4.1.x (Windows AMD64) 的实测逆向。
只读本地文件与已授权采集的明文快照; 不碰微信进程、不做内存扫描、不写源目录。

已确立的事实 (4.1.15.56, xwechat_files 布局):
- 消息表名 = md5(chatroom username), 在 message/message_0.db, 前缀 Msg_。
- local_type 是复合整数: (subtype << 32) | base_type。base 3=图片 34=语音
  43=视频 47=表情 42=名片 49=appmsg; appmsg 子类型 6=文件(在 subtype 槽)。
- 文件消息落盘在 msg/file/<年-月>/ 下, 使用原始文件名 (重名加 (n))。
- 图片落盘在 msg/attach/<md5(chatroom)>/<年-月>/Img/<name>.dat;
  name = 图片内容 md5; 变体后缀: 无=mid, _t=缩略, _h=HD 原图。
- .dat 结构 (部分样本): 31B 固定壳(magic 07 08 56 32)+16B 图片组指纹+
  明文 EXIF(真实宽高在 tag 0x100/0x101)+伪装 SOF0(宽高被改小)+
  明文 JPEG 熵编码主体。
- 大量 .dat 为整文件加密 (AES, 密钥与消息 XML aeskey/db key/进程 hex 候选
  均不同源, 2026-11 时点未能解出; 不要再尝试单字节 XOR——4.x 不是 3.x)。

能力边界:
- plaintext / size-spoofed 两类可直接提取; encrypted 类只能拿明文缩略图缓存
  (cache/<月>/Message/<md5(chatroom)>/Thumb/*.jpg, 文件名带缓存时间戳, 与
  消息发送时间无精确对应, 归属判定需人工核对)。
- 图片的"版权/肖像"内容属于群成员个人, 导出前应确认用途与授权。
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import struct
from dataclasses import dataclass


class MediaError(Exception):
    pass


MAGIC = bytes.fromhex("07085632")
JPEG_SOI = b"\xff\xd8\xff"
JPEG_EOI = b"\xff\xd9"


def chatroom_md5(room: str) -> str:
    """群/联系人 username -> 各目录用的 32 位哈希 (就是 md5)。"""
    return hashlib.md5(room.encode("utf-8")).hexdigest()


def msg_table(room: str) -> str:
    return "Msg_" + chatroom_md5(room)


def is_appmsg_file(local_type: int) -> bool:
    """appmsg 子类型 6 = 文件消息。"""
    return (local_type >> 32) == 6 and (local_type & 0xFFFFFFFF) == 49


def appmsg_type(xml: str) -> int | None:
    m = re.search(r"<type>\s*(\d+)\s*</type>", xml)
    return int(m.group(1)) if m else None


@dataclass
class FileMsg:
    chatroom: str
    title: str
    total_len: int
    md5: str | None
    xml: str


def parse_file_msg(chatroom: str, xml: str) -> FileMsg | None:
    if appmsg_type(xml) != 6:
        return None
    title = re.search(r"<title>(?:<!\[CDATA\[)?(.*?)(?:\]\]>)?</title>", xml, re.S)
    if not title:
        return None
    size = re.search(r"<totallen>(\d+)</totallen>", xml)
    md5 = re.search(r"<md5>([0-9a-f]{32})</md5>", xml)
    return FileMsg(chatroom, title.group(1), int(size.group(1)) if size else 0,
                   md5.group(1) if md5 else None, xml)


@dataclass
class DatProbe:
    kind: str          # plaintext | size_spoofed | encrypted | unknown
    soi_offset: int | None
    eoi_offset: int | None
    sof_w: int | None
    sof_h: int | None
    exif_w: int | None
    exif_h: int | None


def _exif_dimensions(seg: bytes) -> tuple[int | None, int | None]:
    i = seg.find(b"II*\x00")
    if i < 0:
        i = seg.find(b"MM\x00*")
    if i < 0:
        return None, None
    tiff = seg[i:]
    try:
        ifd = struct.unpack("<I", tiff[4:8])[0]
        n = struct.unpack("<H", tiff[ifd:ifd+2])[0]
        w = h = None
        for k in range(n):
            e = tiff[ifd+2+k*12: ifd+2+k*12+12]
            if len(e) < 12:
                break
            tag, _typ, _cnt, val = struct.unpack("<HHII", e)
            if tag == 0x0100:
                w = val
            elif tag == 0x0101:
                h = val
        return w, h
    except struct.error:
        return None, None


def probe_dat(data: bytes) -> DatProbe:
    """判定 .dat 内容类型。只做字节级检查, 不解密。"""
    if not data.startswith(MAGIC):
        return DatProbe("unknown", None, None, None, None, None, None)
    soi = data.find(JPEG_SOI)
    eoi = data.rfind(JPEG_EOI)
    # SOF0 尺寸
    sof_w = sof_h = None
    pos = data.find(b"\xff\xc0")
    if pos >= 0 and pos + 9 <= len(data):
        sof_h, sof_w = struct.unpack(">HH", data[pos+5:pos+9])
    # EXIF 真实尺寸 (头 64KB 内)
    ew, eh = _exif_dimensions(data[:65536])
    if soi >= 0:
        nxt = data[soi+3:soi+4]
        if nxt in (b"\xe0", b"\xe1", b"\xdb", b"\xee"):
            kind = "plaintext"
            # SOF 与 EXIF 尺寸悬殊 => 头是伪装的, 需重建
            if ew and eh and sof_w and sof_h and (ew * eh) > 16 * (sof_w * sof_h):
                kind = "size_spoofed"
            return DatProbe(kind, soi, eoi if eoi > soi else None, sof_w, sof_h, ew, eh)
    kind = "encrypted"
    if ew and eh and sof_w and sof_h and (ew * eh) > 16 * (sof_w * sof_h):
        kind = "size_spoofed_body_unverified"
    return DatProbe(kind, None, None, sof_w, sof_h, ew, eh)


def rebuild_spoofed_jpg(data: bytes) -> bytes:
    """把伪装尺寸的 SOF0 改回 EXIF 真实尺寸, 重拼 JPEG。仅适用于主体明文的样本。"""
    probe = probe_dat(data)
    if probe.exif_w is None or probe.exif_h is None:
        raise MediaError("no EXIF dimensions to rebuild from")
    soi = data.find(JPEG_SOI)
    if soi < 0:
        raise MediaError("no JPEG SOI in dat")
    pos = data.find(b"\xff\xc0", soi)
    if pos < 0:
        raise MediaError("no SOF0 found")
    out = bytearray(data[soi:])  # PIL 要求流以 SOI 开头, 裁掉前置壳
    pos -= soi
    out[pos+5:pos+7] = struct.pack(">H", probe.exif_h)
    out[pos+7:pos+9] = struct.pack(">H", probe.exif_w)
    if probe.eoi_offset is not None and probe.eoi_offset + 2 < len(out):
        del out[probe.eoi_offset+2-soi:]  # EOI 之后的尾段会打断解码
    return bytes(out)


def extract_plaintext_jpg(data: bytes) -> bytes:
    probe = probe_dat(data)
    if probe.kind != "plaintext" or probe.soi_offset is None or probe.eoi_offset is None:
        raise MediaError(f"not a plaintext jpeg dat (kind={probe.kind})")
    return data[probe.soi_offset:probe.eoi_offset+2]


def decode_dat_image(path: str, max_bytes: int = 120_000_000):
    """高位入口: .dat path -> PIL Image (或抛 MediaError)。

    - plaintext: 直接 SOI..EOI 截取;
    - size_spoofed: 重建 SOF 尺寸后用 LOAD_TRUNCATED_IMAGES 解码。
      实测主体可完整解码, 尾部可能有加密洞——重要图片需人工核对完整性。
    - encrypted: 本地密钥与消息 aeskey/db key 均不同源, 暂不可解 (2026-11)。
    """
    size = os.path.getsize(path)
    if size > max_bytes:
        raise MediaError(f"dat too large: {size}")
    data = open(path, "rb").read()
    probe = probe_dat(data)
    if probe.kind == "encrypted":
        raise MediaError("image body is encrypted; no key path as of 2026-11")
    if probe.kind == "plaintext":
        return _load_pil(extract_plaintext_jpg(data))
    if probe.kind == "size_spoofed":
        return _load_pil(rebuild_spoofed_jpg(data))
    raise MediaError(f"unknown dat layout: {probe.kind}")


def _load_pil(jpg: bytes):
    from PIL import Image, ImageFile
    ImageFile.LOAD_TRUNCATED_IMAGES = True
    im = Image.open(io.BytesIO(jpg))
    im.load()
    return im


def docx_text(path: str) -> str:
    """docx -> 纯文本 (zipfile + word/document.xml), 无第三方依赖。"""
    import zipfile
    with zipfile.ZipFile(path) as z:
        xml = z.read("word/document.xml").decode("utf-8", "ignore")
    xml = re.sub(r"</w:p>", "\n", xml)
    xml = re.sub(r"<[^>]+>", "", xml)
    return xml


def match_files_on_disk(wxroot: str, msgs: list[FileMsg]) -> dict[str, str]:
    """文件消息按原始文件名在 msg/file/ 下找落盘文件 (重名取第一个)。"""
    disk: dict[str, list[str]] = {}
    root = os.path.join(wxroot, "msg", "file")
    for base, _ds, fs in os.walk(root):
        for f in fs:
            disk.setdefault(f, []).append(os.path.join(base, f))
    out = {}
    for m in msgs:
        cands = disk.get(m.title) or disk.get(m.title.replace(" ", ""))
        if cands:
            out[m.title] = cands[0]
    return out


def collect_thumb_cache(wxroot: str, room: str) -> list[tuple[int, str]]:
    """明文缩略图缓存 (文件名 <id>_<unixts>_thumb.jpg), 按时间升序。

    注意: 时间戳是缓存生成时间, 不等于消息发送时间; 归属需人工核对。
    """
    md5v = chatroom_md5(room)
    root = os.path.join(wxroot, "cache")
    out = []
    for base, _ds, fs in os.walk(root):
        if md5v not in base.split(os.sep):
            continue
        for f in fs:
            m = re.match(r"(\d+)_(\d+)_thumb", f)
            if f.endswith(".jpg") and m:
                out.append((int(m.group(2)), os.path.join(base, f)))
    out.sort()
    return out


def _selftest():
    # 1) md5 / 表名 (自洽断言, 不含真实账号数据)
    room = "12345678901@chatroom"
    assert chatroom_md5(room) == hashlib.md5(room.encode("utf-8")).hexdigest()
    assert msg_table(room) == "Msg_" + chatroom_md5(room)
    # 2) 复合类型
    assert is_appmsg_file(25769803825)     # (6<<32)|49 文件
    assert not is_appmsg_file(244813135921)  # 合并转发
    assert (244813135921 >> 32) == 57 and (244813135921 & 0xFFFFFFFF) == 49
    # 3) 文件消息解析
    xml = '<msg><appmsg appid=""><title>1、本草-紫苏.docx</title><type>6</type>' \
          '<appattach><totallen>123</totallen></appattach></appmsg></msg>'
    fm = parse_file_msg("x@chatroom", xml)
    assert fm and fm.title.endswith(".docx") and fm.total_len == 123
    assert parse_file_msg("x@chatroom", "<msg><appmsg><title>a</title><type>5</type></appmsg></msg>") is None
    # 4) EXIF 尺寸提取
    tiff = b"II*\x00" + struct.pack("<I", 8) + struct.pack("<H", 2) + \
        struct.pack("<HHII", 0x0100, 4, 1, 7728) + struct.pack("<HHII", 0x0101, 4, 1, 5152)
    assert _exif_dimensions(b"junk" + tiff) == (7728, 5152)
    # 5) 明文提取
    fake_jpg = JPEG_SOI + b"\xe0" + b"\x00" * 8 + JPEG_EOI
    assert extract_plaintext_jpg(MAGIC + fake_jpg) == fake_jpg
    # 6) 伪装判定: 密文无 SOI 但 EXIF 巨大
    probe = probe_dat(MAGIC + b"\x10" * 100 + b"junk" + tiff + b"\x00" * 64)
    assert probe.kind in ("encrypted", "size_spoofed_body_unverified"), probe.kind
    print("self-test ok")


if __name__ == "__main__":
    _selftest()
