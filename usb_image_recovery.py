#!/usr/bin/env python3
"""Recover contiguous image files from a USB device or disk image.

The program only opens the source for reading. Recovery uses file carving, so
files that are fragmented may be incomplete and existing images may also be
found alongside deleted ones.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO, Callable, Iterable, Iterator


KIB = 1024
MIB = 1024 * KIB
DEFAULT_CHUNK_SIZE = 8 * MIB
DEFAULT_MAX_FILE_SIZE = 512 * MIB
COPY_CHUNK_SIZE = 1 * MIB
WINDOWS_SECTOR_SIZE = 512


class InvalidImage(ValueError):
    """Raised when bytes at an offset do not form a supported image."""


@dataclass(frozen=True)
class FormatSpec:
    name: str
    extension: str
    signatures: tuple[bytes, ...]
    parser: Callable[[BinaryIO, int, int], int]


@dataclass
class RecoveryStats:
    candidates: int = 0
    recovered: int = 0
    duplicates: int = 0
    rejected: int = 0
    bytes_written: int = 0
    rejection_reasons: dict[str, int] = field(default_factory=dict)


class AlignedDeviceReader:
    """Expose normal seek/read semantics over a sector-aligned raw device."""

    def __init__(
        self,
        raw: BinaryIO,
        alignment: int = WINDOWS_SECTOR_SIZE,
        size: int | None = None,
    ) -> None:
        self.raw = raw
        self.alignment = alignment
        self.size = size
        self.position = 0

    def tell(self) -> int:
        return self.position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self.position + offset
        elif whence == os.SEEK_END and self.size is not None:
            position = self.size + offset
        else:
            raise OSError("seek relatif terhadap akhir memerlukan ukuran device")
        if position < 0:
            raise OSError("tidak dapat seek ke offset negatif")
        self.position = position
        return position

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            if self.size is None:
                raise OSError("pembacaan tanpa batas memerlukan ukuran device")
            size = self.size - self.position
        if size == 0 or (self.size is not None and self.position >= self.size):
            return b""
        if self.size is not None:
            size = min(size, self.size - self.position)

        aligned_start = self.position - (self.position % self.alignment)
        prefix = self.position - aligned_start
        needed = prefix + size
        aligned_size = (
            (needed + self.alignment - 1) // self.alignment * self.alignment
        )
        if self.size is not None:
            aligned_size = min(aligned_size, self.size - aligned_start)

        self.raw.seek(aligned_start)
        data = self.raw.read(aligned_size)
        result = data[prefix : prefix + size]
        self.position += len(result)
        return result


def windows_device_size(raw: BinaryIO) -> int | None:
    if os.name != "nt":
        return None
    import msvcrt

    ioctl_disk_get_length_info = 0x0007405C
    length = ctypes.c_longlong()
    returned = ctypes.c_ulong()
    handle = msvcrt.get_osfhandle(raw.fileno())
    success = ctypes.windll.kernel32.DeviceIoControl(
        handle,
        ioctl_disk_get_length_info,
        None,
        0,
        ctypes.byref(length),
        ctypes.sizeof(length),
        ctypes.byref(returned),
        None,
    )
    return length.value if success else None


def filesystem_size_from_boot_sector(boot: bytes) -> int | None:
    if len(boot) < 512:
        return None
    if boot[3:11] == b"EXFAT   ":
        sector_shift = boot[108]
        if 9 <= sector_shift <= 12:
            return struct.unpack_from("<Q", boot, 72)[0] << sector_shift
        return None

    bytes_per_sector = struct.unpack_from("<H", boot, 11)[0]
    if bytes_per_sector not in (512, 1024, 2048, 4096):
        return None
    total_sectors_16 = struct.unpack_from("<H", boot, 19)[0]
    total_sectors = total_sectors_16 or struct.unpack_from("<I", boot, 32)[0]
    return total_sectors * bytes_per_sector if total_sectors else None


@contextlib.contextmanager
def open_source(path: str) -> Iterator[BinaryIO]:
    raw = open(path, "rb", buffering=0)
    try:
        if os.name == "nt" and re.match(r"^\\\\\.\\[A-Za-z]:$", path):
            boot = raw.read(WINDOWS_SECTOR_SIZE)
            raw.seek(0)
            size = filesystem_size_from_boot_sector(boot)
            yield AlignedDeviceReader(raw, size=size or windows_device_size(raw))
        else:
            yield raw
    finally:
        raw.close()


def read_exact(source: BinaryIO, size: int) -> bytes:
    data = source.read(size)
    if len(data) != size:
        raise InvalidImage("unexpected end of source")
    return data


def parse_jpeg(source: BinaryIO, offset: int, max_size: int) -> int:
    source.seek(offset)
    if read_exact(source, 2) != b"\xff\xd8":
        raise InvalidImage("invalid JPEG header")

    consumed = 2
    saw_frame = False
    pending_marker: int | None = None
    frame_markers = set(range(0xC0, 0xC4)) | set(range(0xC5, 0xC8))
    frame_markers |= set(range(0xC9, 0xCC)) | set(range(0xCD, 0xD0))

    while consumed < max_size:
        if pending_marker is None:
            if read_exact(source, 1) != b"\xff":
                raise InvalidImage("invalid JPEG marker boundary")
            consumed += 1
            marker = read_exact(source, 1)[0]
            consumed += 1
            while marker == 0xFF:
                marker = read_exact(source, 1)[0]
                consumed += 1
        else:
            marker = pending_marker
            pending_marker = None

        if marker == 0xD9:
            if not saw_frame:
                raise InvalidImage("JPEG has no image frame")
            return consumed
        if marker in frame_markers:
            saw_frame = True
        if marker in (0x01, 0xD8) or 0xD0 <= marker <= 0xD7:
            continue

        segment_length = struct.unpack(">H", read_exact(source, 2))[0]
        consumed += 2
        if segment_length < 2 or consumed + segment_length - 2 > max_size:
            raise InvalidImage("invalid JPEG segment size")
        source.seek(segment_length - 2, os.SEEK_CUR)
        consumed += segment_length - 2

        if marker != 0xDA:
            continue

        previous_ff = False
        while consumed < max_size:
            chunk = source.read(min(64 * KIB, max_size - consumed))
            if not chunk:
                raise InvalidImage("JPEG scan data is incomplete")
            marker_index: int | None = None
            for index, value in enumerate(chunk):
                if not previous_ff:
                    previous_ff = value == 0xFF
                    continue
                if value == 0x00 or 0xD0 <= value <= 0xD7:
                    previous_ff = False
                    continue
                if value == 0xFF:
                    continue
                marker_index = index
                pending_marker = value
                break
            if marker_index is None:
                consumed += len(chunk)
                continue
            unread = len(chunk) - marker_index - 1
            if unread:
                source.seek(-unread, os.SEEK_CUR)
            consumed += marker_index + 1
            break
    raise InvalidImage("JPEG end marker not found within size limit")


def parse_png(source: BinaryIO, offset: int, max_size: int) -> int:
    source.seek(offset)
    if read_exact(source, 8) != b"\x89PNG\r\n\x1a\n":
        raise InvalidImage("invalid PNG header")

    position = 8
    saw_ihdr = False
    while position + 12 <= max_size:
        length, chunk_type = struct.unpack(">I4s", read_exact(source, 8))
        if length > max_size - position - 12:
            raise InvalidImage("PNG chunk exceeds size limit")
        if not saw_ihdr:
            if chunk_type != b"IHDR" or length != 13:
                raise InvalidImage("invalid PNG IHDR")
            saw_ihdr = True
        source.seek(length + 4, os.SEEK_CUR)
        position += 12 + length
        if chunk_type == b"IEND":
            if length != 0:
                raise InvalidImage("invalid PNG IEND")
            return position
    raise InvalidImage("PNG IEND chunk not found")


def skip_gif_sub_blocks(source: BinaryIO, consumed: int, max_size: int) -> int:
    while consumed < max_size:
        block_size = read_exact(source, 1)[0]
        consumed += 1
        if block_size == 0:
            return consumed
        if consumed + block_size > max_size:
            raise InvalidImage("GIF sub-block exceeds size limit")
        source.seek(block_size, os.SEEK_CUR)
        consumed += block_size
    raise InvalidImage("unterminated GIF sub-blocks")


def parse_gif(source: BinaryIO, offset: int, max_size: int) -> int:
    source.seek(offset)
    header = read_exact(source, 13)
    if header[:6] not in (b"GIF87a", b"GIF89a"):
        raise InvalidImage("invalid GIF header")
    width, height = struct.unpack("<HH", header[6:10])
    if width == 0 or height == 0:
        raise InvalidImage("invalid GIF dimensions")

    consumed = 13
    if header[10] & 0x80:
        table_size = 3 * (2 ** ((header[10] & 0x07) + 1))
        if consumed + table_size > max_size:
            raise InvalidImage("GIF color table exceeds size limit")
        source.seek(table_size, os.SEEK_CUR)
        consumed += table_size

    while consumed < max_size:
        introducer = read_exact(source, 1)[0]
        consumed += 1
        if introducer == 0x3B:
            return consumed
        if introducer == 0x21:
            read_exact(source, 1)
            consumed += 1
            consumed = skip_gif_sub_blocks(source, consumed, max_size)
            continue
        if introducer == 0x2C:
            descriptor = read_exact(source, 9)
            consumed += 9
            if descriptor[8] & 0x80:
                table_size = 3 * (2 ** ((descriptor[8] & 0x07) + 1))
                if consumed + table_size > max_size:
                    raise InvalidImage("GIF local color table exceeds limit")
                source.seek(table_size, os.SEEK_CUR)
                consumed += table_size
            read_exact(source, 1)  # LZW minimum code size
            consumed += 1
            consumed = skip_gif_sub_blocks(source, consumed, max_size)
            continue
        raise InvalidImage("unknown GIF block")
    raise InvalidImage("GIF trailer not found")


def parse_bmp(source: BinaryIO, offset: int, max_size: int) -> int:
    source.seek(offset)
    header = read_exact(source, 30)
    if header[:2] != b"BM":
        raise InvalidImage("invalid BMP header")
    file_size = struct.unpack_from("<I", header, 2)[0]
    pixel_offset = struct.unpack_from("<I", header, 10)[0]
    dib_size = struct.unpack_from("<I", header, 14)[0]
    if dib_size not in (12, 16, 40, 52, 56, 64, 108, 124):
        raise InvalidImage("unsupported BMP DIB header")
    if dib_size == 12:
        width, height = struct.unpack_from("<HH", header, 18)
    else:
        width, height = struct.unpack_from("<ii", header, 18)
    if file_size < 26 or file_size > max_size or pixel_offset >= file_size:
        raise InvalidImage("invalid BMP size")
    if width == 0 or height == 0:
        raise InvalidImage("invalid BMP dimensions")
    return file_size


def parse_webp(source: BinaryIO, offset: int, max_size: int) -> int:
    source.seek(offset)
    header = read_exact(source, 16)
    if header[:4] != b"RIFF" or header[8:12] != b"WEBP":
        raise InvalidImage("invalid WebP header")
    file_size = struct.unpack_from("<I", header, 4)[0] + 8
    if file_size < 20 or file_size > max_size:
        raise InvalidImage("invalid WebP size")
    if header[12:16] not in (b"VP8 ", b"VP8L", b"VP8X"):
        raise InvalidImage("unknown WebP image chunk")
    return file_size


TIFF_TYPE_SIZES = {
    1: 1,   # BYTE
    2: 1,   # ASCII
    3: 2,   # SHORT
    4: 4,   # LONG
    5: 8,   # RATIONAL
    6: 1,   # SBYTE
    7: 1,   # UNDEFINED
    8: 2,   # SSHORT
    9: 4,   # SLONG
    10: 8,  # SRATIONAL
    11: 4,  # FLOAT
    12: 8,  # DOUBLE
}


def tiff_values(
    source: BinaryIO,
    base: int,
    endian: str,
    value_type: int,
    count: int,
    value_field: bytes,
    max_size: int,
) -> list[int]:
    type_size = TIFF_TYPE_SIZES.get(value_type)
    if type_size is None or count > 1_000_000:
        return []
    total_size = type_size * count
    if total_size <= 4:
        raw = value_field[:total_size]
    else:
        data_offset = struct.unpack(endian + "I", value_field)[0]
        if data_offset + total_size > max_size:
            raise InvalidImage("TIFF value data exceeds size limit")
        source.seek(base + data_offset)
        raw = read_exact(source, total_size)

    if value_type == 3:
        return list(struct.unpack(endian + f"{count}H", raw))
    if value_type == 4:
        return list(struct.unpack(endian + f"{count}I", raw))
    return []


def parse_tiff(source: BinaryIO, offset: int, max_size: int) -> int:
    source.seek(offset)
    header = read_exact(source, 8)
    if header[:2] == b"II":
        endian = "<"
    elif header[:2] == b"MM":
        endian = ">"
    else:
        raise InvalidImage("invalid TIFF byte order")
    if struct.unpack(endian + "H", header[2:4])[0] != 42:
        raise InvalidImage("invalid TIFF magic")

    pending = [struct.unpack(endian + "I", header[4:8])[0]]
    visited: set[int] = set()
    max_end = 8
    strip_offsets: list[int] = []
    strip_sizes: list[int] = []
    tile_offsets: list[int] = []
    tile_sizes: list[int] = []
    jpeg_offsets: list[int] = []
    jpeg_sizes: list[int] = []

    while pending and len(visited) < 64:
        ifd_offset = pending.pop()
        if ifd_offset == 0 or ifd_offset in visited:
            continue
        if ifd_offset + 2 > max_size:
            raise InvalidImage("TIFF IFD exceeds size limit")
        visited.add(ifd_offset)
        source.seek(offset + ifd_offset)
        entry_count = struct.unpack(endian + "H", read_exact(source, 2))[0]
        if entry_count > 4096:
            raise InvalidImage("unreasonable TIFF entry count")
        ifd_end = ifd_offset + 2 + entry_count * 12 + 4
        if ifd_end > max_size:
            raise InvalidImage("TIFF IFD exceeds size limit")
        max_end = max(max_end, ifd_end)

        entries = read_exact(source, entry_count * 12)
        next_ifd = struct.unpack(endian + "I", read_exact(source, 4))[0]
        if next_ifd:
            pending.append(next_ifd)

        for index in range(entry_count):
            entry = entries[index * 12 : (index + 1) * 12]
            tag, value_type, count = struct.unpack(endian + "HHI", entry[:8])
            type_size = TIFF_TYPE_SIZES.get(value_type)
            if type_size is None:
                continue
            total_size = type_size * count
            if total_size > 4:
                data_offset = struct.unpack(endian + "I", entry[8:12])[0]
                if data_offset + total_size > max_size:
                    raise InvalidImage("TIFF metadata exceeds size limit")
                max_end = max(max_end, data_offset + total_size)
            values = tiff_values(
                source, offset, endian, value_type, count, entry[8:12], max_size
            )
            if tag == 273:
                strip_offsets = values
            elif tag == 279:
                strip_sizes = values
            elif tag == 324:
                tile_offsets = values
            elif tag == 325:
                tile_sizes = values
            elif tag == 513:
                jpeg_offsets = values
            elif tag == 514:
                jpeg_sizes = values
            elif tag in (330, 34665, 34853):
                pending.extend(values)

    for offsets, sizes in (
        (strip_offsets, strip_sizes),
        (tile_offsets, tile_sizes),
        (jpeg_offsets, jpeg_sizes),
    ):
        if len(sizes) == 1 and len(offsets) > 1:
            sizes = sizes * len(offsets)
        for data_offset, data_size in zip(offsets, sizes):
            if data_offset + data_size > max_size:
                raise InvalidImage("TIFF image data exceeds size limit")
            max_end = max(max_end, data_offset + data_size)

    if not visited or max_end < 16:
        raise InvalidImage("incomplete TIFF structure")
    return max_end


FORMATS = {
    "jpg": FormatSpec("JPEG", "jpg", (b"\xff\xd8\xff",), parse_jpeg),
    "png": FormatSpec("PNG", "png", (b"\x89PNG\r\n\x1a\n",), parse_png),
    "gif": FormatSpec("GIF", "gif", (b"GIF87a", b"GIF89a"), parse_gif),
    "bmp": FormatSpec("BMP", "bmp", (b"BM",), parse_bmp),
    "webp": FormatSpec("WebP", "webp", (b"RIFF",), parse_webp),
    "tiff": FormatSpec(
        "TIFF", "tiff", (b"II*\x00", b"MM\x00*"), parse_tiff
    ),
}


def detect_filesystem(source: BinaryIO) -> str:
    original = source.tell()
    try:
        source.seek(0)
        boot = source.read(512)
    finally:
        source.seek(original)
    if len(boot) >= 11 and boot[3:11] == b"EXFAT   ":
        return "exFAT"
    if len(boot) >= 90 and boot[82:90] == b"FAT32   ":
        return "FAT32"
    if len(boot) >= 62 and boot[54:62] in (b"FAT16   ", b"FAT12   "):
        return boot[54:62].decode("ascii").strip()
    return "unknown/raw image"


def get_source_size(source: BinaryIO) -> int | None:
    try:
        current = source.tell()
        source.seek(0, os.SEEK_END)
        size = source.tell()
        source.seek(current)
        return size
    except OSError:
        return None


def windows_removable_drives() -> list[dict[str, str]]:
    kernel32 = ctypes.windll.kernel32
    mask = kernel32.GetLogicalDrives()
    drives: list[dict[str, str]] = []
    for index in range(26):
        if not mask & (1 << index):
            continue
        letter = chr(ord("A") + index)
        root = f"{letter}:\\"
        if kernel32.GetDriveTypeW(root) != 2:  # DRIVE_REMOVABLE
            continue
        volume_name = ctypes.create_unicode_buffer(261)
        filesystem = ctypes.create_unicode_buffer(261)
        kernel32.GetVolumeInformationW(
            root,
            volume_name,
            len(volume_name),
            None,
            None,
            None,
            filesystem,
            len(filesystem),
        )
        drives.append(
            {
                "source": rf"\\.\{letter}:",
                "mount": root,
                "label": volume_name.value or "-",
                "filesystem": filesystem.value or "unknown",
            }
        )
    return drives


def linux_removable_drives() -> list[dict[str, str]]:
    try:
        result = subprocess.run(
            ["lsblk", "-Jpo", "NAME,RM,TYPE,FSTYPE,LABEL,MOUNTPOINTS"],
            check=True,
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
    except (OSError, subprocess.CalledProcessError, json.JSONDecodeError):
        return []

    drives: list[dict[str, str]] = []

    def visit(node: dict[str, object], inherited_removable: bool = False) -> None:
        removable = inherited_removable or bool(node.get("rm"))
        node_type = str(node.get("type", ""))
        filesystem = node.get("fstype")
        if removable and node_type in ("part", "disk") and filesystem:
            mountpoints = node.get("mountpoints") or []
            mount = next((item for item in mountpoints if item), "-")
            drives.append(
                {
                    "source": str(node.get("name")),
                    "mount": str(mount),
                    "label": str(node.get("label") or "-"),
                    "filesystem": str(filesystem),
                }
            )
        for child in node.get("children") or []:
            visit(child, removable)

    for block_device in data.get("blockdevices", []):
        visit(block_device)
    return drives


def list_removable_drives() -> list[dict[str, str]]:
    if os.name == "nt":
        return windows_removable_drives()
    if sys.platform.startswith("linux"):
        return linux_removable_drives()
    return []


def linux_parent_disk(device: str) -> str:
    name = Path(os.path.realpath(device)).name
    sys_path = Path("/sys/class/block") / name
    try:
        if (sys_path / "partition").exists():
            return sys_path.resolve().parent.name
    except OSError:
        pass
    return name


def mounted_device_for_path(path: Path) -> str | None:
    if not sys.platform.startswith("linux"):
        return None
    resolved = str(path.resolve())
    best_mount = ""
    best_device: str | None = None
    try:
        with open("/proc/self/mounts", encoding="utf-8") as mounts:
            for line in mounts:
                fields = line.split()
                if len(fields) < 2:
                    continue
                device = fields[0].replace("\\040", " ")
                mount = fields[1].replace("\\040", " ")
                if resolved == mount or resolved.startswith(mount.rstrip("/") + "/"):
                    if len(mount) > len(best_mount):
                        best_mount = mount
                        best_device = device
    except OSError:
        return None
    return best_device


def ensure_safe_output(source_path: str, output_dir: Path) -> None:
    output_resolved = output_dir.resolve()

    try:
        source_resolved = Path(source_path).resolve()
        if source_resolved == output_resolved or source_resolved in output_resolved.parents:
            raise ValueError("folder output berada di dalam sumber yang dipindai")
    except OSError:
        pass

    if os.name == "nt":
        match = re.match(r"^\\\\\.\\([A-Za-z]):", source_path)
        if match and output_resolved.drive.upper() == f"{match.group(1).upper()}:":
            raise ValueError("folder output berada pada USB sumber")
    elif source_path.startswith("/dev/"):
        output_device = mounted_device_for_path(output_resolved)
        if output_device and output_device.startswith("/dev/"):
            if linux_parent_disk(source_path) == linux_parent_disk(output_device):
                raise ValueError("folder output berada pada USB sumber")
    output_dir.mkdir(parents=True, exist_ok=True)


def find_candidates(
    data: bytes,
    data_offset: int,
    specs: Iterable[FormatSpec],
) -> list[tuple[int, FormatSpec]]:
    candidates: list[tuple[int, FormatSpec]] = []
    for spec in specs:
        for signature in spec.signatures:
            start = 0
            while True:
                index = data.find(signature, start)
                if index < 0:
                    break
                candidates.append((data_offset + index, spec))
                start = index + 1
    candidates.sort(key=lambda item: item[0])
    return candidates


def hash_range(source: BinaryIO, offset: int, size: int) -> str:
    digest = hashlib.sha256()
    source.seek(offset)
    remaining = size
    while remaining:
        chunk = source.read(min(COPY_CHUNK_SIZE, remaining))
        if not chunk:
            raise InvalidImage("source ended while hashing")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def copy_range(source: BinaryIO, offset: int, size: int, destination: Path) -> None:
    source.seek(offset)
    remaining = size
    with destination.open("xb") as output:
        try:
            while remaining:
                chunk = source.read(min(COPY_CHUNK_SIZE, remaining))
                if not chunk:
                    raise InvalidImage("source ended while copying")
                output.write(chunk)
                remaining -= len(chunk)
            output.flush()
            os.fsync(output.fileno())
        except Exception:
            output.close()
            destination.unlink(missing_ok=True)
            raise


def recover(
    source: BinaryIO,
    output_dir: Path | None,
    specs: list[FormatSpec],
    chunk_size: int,
    max_file_size: int,
    min_file_size: int,
    start_offset: int,
    scan_size: int | None,
    dry_run: bool,
    keep_duplicates: bool,
    quiet: bool,
    verbose: bool = False,
) -> RecoveryStats:
    stats = RecoveryStats()
    overlap_size = max(len(sig) for spec in specs for sig in spec.signatures) - 1
    source_size = get_source_size(source)
    scan_end = None if scan_size is None else start_offset + scan_size
    if source_size is not None:
        scan_end = min(source_size, scan_end) if scan_end else source_size

    seen_offsets: set[tuple[int, str]] = set()
    seen_hashes: set[str] = set()
    tail = b""
    position = start_offset
    last_progress = 0.0
    source.seek(position)

    while scan_end is None or position < scan_end:
        request_size = chunk_size
        if scan_end is not None:
            request_size = min(request_size, scan_end - position)
        chunk = source.read(request_size)
        if not chunk:
            break

        data = tail + chunk
        data_offset = position - len(tail)
        for candidate_offset, spec in find_candidates(data, data_offset, specs):
            key = (candidate_offset, spec.extension)
            if key in seen_offsets or candidate_offset < start_offset:
                continue
            seen_offsets.add(key)
            stats.candidates += 1
            scan_position = source.tell()
            try:
                available = max_file_size
                if source_size is not None:
                    available = min(available, source_size - candidate_offset)
                file_size = spec.parser(source, candidate_offset, available)
                if file_size < min_file_size:
                    raise InvalidImage("candidate is smaller than minimum size")
                digest = hash_range(source, candidate_offset, file_size)
                if digest in seen_hashes and not keep_duplicates:
                    stats.duplicates += 1
                    continue
                seen_hashes.add(digest)

                filename = (
                    f"{stats.recovered + 1:06d}_{spec.extension}_"
                    f"offset-{candidate_offset:016x}_{digest[:12]}.{spec.extension}"
                )
                if not dry_run:
                    if output_dir is None:
                        raise RuntimeError("output directory is required")
                    copy_range(source, candidate_offset, file_size, output_dir / filename)
                    stats.bytes_written += file_size
                stats.recovered += 1
                if not quiet:
                    action = "KANDIDAT" if dry_run else "PULIH"
                    print(
                        f"[{action}] {filename} ({file_size / KIB:.1f} KiB)",
                        flush=True,
                    )
            except (InvalidImage, OSError, struct.error) as error:
                stats.rejected += 1
                reason = f"{spec.name}: {error}"
                stats.rejection_reasons[reason] = (
                    stats.rejection_reasons.get(reason, 0) + 1
                )
                if verbose:
                    print(
                        f"[TOLAK] {spec.name} offset 0x{candidate_offset:x}: {error}",
                        file=sys.stderr,
                    )
            finally:
                source.seek(scan_position)

        position += len(chunk)
        tail = data[-overlap_size:] if overlap_size else b""
        now = time.monotonic()
        if not quiet and now - last_progress >= 1.0:
            if scan_end:
                percent = min(100.0, position / scan_end * 100)
                print(
                    f"\rMemindai: {percent:6.2f}% "
                    f"({position / MIB:,.1f}/{scan_end / MIB:,.1f} MiB)",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
            else:
                print(
                    f"\rMemindai: {position / MIB:,.1f} MiB",
                    end="",
                    file=sys.stderr,
                    flush=True,
                )
            last_progress = now
        source.seek(position)

    if not quiet:
        print(file=sys.stderr)
    return stats


def parse_formats(value: str) -> list[FormatSpec]:
    names = [item.strip().lower() for item in value.split(",") if item.strip()]
    if "all" in names:
        names = list(FORMATS)
    aliases = {"jpeg": "jpg", "tif": "tiff"}
    names = [aliases.get(name, name) for name in names]
    unknown = sorted(set(names) - set(FORMATS))
    if unknown:
        raise argparse.ArgumentTypeError(
            f"format tidak dikenal: {', '.join(unknown)}"
        )
    return [FORMATS[name] for name in dict.fromkeys(names)]


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("nilai harus lebih dari nol")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Pulihkan gambar yang tersimpan secara kontigu dari USB FAT32/exFAT "
            "atau disk image. Sumber selalu dibuka read-only."
        )
    )
    parser.add_argument(
        "source",
        nargs="?",
        help=r"device atau image, misalnya \\.\E: atau /dev/sdb1",
    )
    parser.add_argument(
        "-o", "--output", type=Path, help="folder output pada drive komputer"
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="tampilkan USB removable yang terdeteksi lalu keluar",
    )
    parser.add_argument(
        "--formats",
        type=parse_formats,
        default=parse_formats("all"),
        metavar="LIST",
        help="all atau daftar: jpg,png,gif,bmp,webp,tiff (default: all)",
    )
    parser.add_argument(
        "--chunk-mib",
        type=positive_int,
        default=DEFAULT_CHUNK_SIZE // MIB,
        help="ukuran blok pemindaian dalam MiB (default: 8)",
    )
    parser.add_argument(
        "--max-file-mib",
        type=positive_int,
        default=DEFAULT_MAX_FILE_SIZE // MIB,
        help="ukuran maksimum satu gambar dalam MiB (default: 512)",
    )
    parser.add_argument(
        "--min-file-kib",
        type=positive_int,
        default=1,
        help="ukuran minimum hasil dalam KiB (default: 1)",
    )
    parser.add_argument(
        "--start-offset",
        type=lambda value: int(value, 0),
        default=0,
        help="offset mulai dalam byte; menerima 0x... (default: 0)",
    )
    parser.add_argument(
        "--scan-mib",
        type=positive_int,
        help="batasi jumlah data yang dipindai, berguna untuk pengujian",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="validasi dan tampilkan kandidat tanpa menulis file",
    )
    parser.add_argument(
        "--keep-duplicates",
        action="store_true",
        help="simpan file dengan isi identik lebih dari sekali",
    )
    parser.add_argument("--quiet", action="store_true", help="kurangi output")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="tampilkan offset dan alasan setiap kandidat ditolak",
    )
    return parser


def print_drive_list() -> int:
    drives = list_removable_drives()
    if not drives:
        print("Tidak ada USB removable yang terdeteksi.")
        return 1
    print(f"{'SOURCE':<22} {'FILESYSTEM':<12} {'LABEL':<20} MOUNT")
    for drive in drives:
        print(
            f"{drive['source']:<22} {drive['filesystem']:<12} "
            f"{drive['label']:<20} {drive['mount']}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list:
        return print_drive_list()
    if not args.source:
        parser.error("source wajib diberikan kecuali saat memakai --list")
    if not args.dry_run and args.output is None:
        parser.error("--output wajib diberikan kecuali saat memakai --dry-run")
    if args.start_offset < 0:
        parser.error("--start-offset tidak boleh negatif")

    try:
        if args.output is not None:
            ensure_safe_output(args.source, args.output)
        with open_source(args.source) as source:
            filesystem = detect_filesystem(source)
            source_size = get_source_size(source)
            if not args.quiet:
                size_text = (
                    f"{source_size / (1024 ** 3):,.2f} GiB"
                    if source_size is not None
                    else "tidak diketahui"
                )
                print(f"Sumber     : {args.source}")
                print(f"Filesystem : {filesystem}")
                print(f"Ukuran     : {size_text}")
                print(
                    "Format     : "
                    + ", ".join(spec.name for spec in args.formats)
                )
                if args.dry_run:
                    print("Mode       : dry-run (tidak menulis hasil)")
            stats = recover(
                source=source,
                output_dir=args.output,
                specs=args.formats,
                chunk_size=args.chunk_mib * MIB,
                max_file_size=args.max_file_mib * MIB,
                min_file_size=args.min_file_kib * KIB,
                start_offset=args.start_offset,
                scan_size=args.scan_mib * MIB if args.scan_mib else None,
                dry_run=args.dry_run,
                keep_duplicates=args.keep_duplicates,
                quiet=args.quiet,
                verbose=args.verbose,
            )
    except PermissionError:
        print(
            "Akses ditolak. Jalankan terminal sebagai Administrator (Windows) "
            "atau gunakan sudo/root (Linux).",
            file=sys.stderr,
        )
        return 2
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    print(
        f"Selesai: {stats.recovered} gambar ditemukan, "
        f"{stats.duplicates} duplikat dilewati, "
        f"{stats.rejected} kandidat tidak valid."
    )
    if not args.dry_run:
        print(f"Data ditulis: {stats.bytes_written / MIB:,.2f} MiB")
    if stats.rejection_reasons and not args.quiet:
        print("Alasan penolakan terbanyak:")
        reasons = sorted(
            stats.rejection_reasons.items(), key=lambda item: item[1], reverse=True
        )
        for reason, count in reasons[:5]:
            print(f"  {count:4d}x {reason}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
