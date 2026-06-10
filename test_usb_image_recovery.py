import contextlib
import io
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

import usb_image_recovery as recovery


def png_chunk(name: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + name
        + data
        + struct.pack(">I", zlib.crc32(name + data) & 0xFFFFFFFF)
    )


def make_png() -> bytes:
    header = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    image_data = zlib.compress(b"\x00\xff\x00\x00")
    return (
        header
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", image_data)
        + png_chunk(b"IEND", b"")
    )


def make_bmp() -> bytes:
    pixels = b"\x00\x00\xff\x00"
    size = 14 + 40 + len(pixels)
    return (
        b"BM"
        + struct.pack("<IHHI", size, 0, 0, 54)
        + struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixels), 0, 0, 0, 0)
        + pixels
    )


def make_jpeg() -> bytes:
    app_data = b"metadata containing an embedded marker \xff\xd9 safely"
    app = b"\xff\xe1" + struct.pack(">H", len(app_data) + 2) + app_data
    frame_data = b"\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    frame = b"\xff\xc0" + struct.pack(">H", len(frame_data) + 2) + frame_data
    scan_header = b"\x01\x01\x00\x00\x3f\x00"
    scan = b"\xff\xda" + struct.pack(">H", len(scan_header) + 2) + scan_header
    entropy = b"\x12\xff\x00\x34\xff\xd0\x56"
    return b"\xff\xd8" + app + frame + scan + entropy + b"\xff\xd9"


def make_gif() -> bytes:
    return (
        b"GIF89a"
        + struct.pack("<HH", 1, 1)
        + b"\x80\x00\x00"
        + b"\x00\x00\x00\xff\xff\xff"
        + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00"
        + b"\x02\x02\x4c\x01\x00"
        + b"\x3b"
    )


def make_tiff() -> bytes:
    # Little-endian, one IFD containing width and a single image strip.
    entries = (
        struct.pack("<HHI4s", 256, 4, 1, struct.pack("<I", 1))
        + struct.pack("<HHI4s", 273, 4, 1, struct.pack("<I", 50))
        + struct.pack("<HHI4s", 279, 4, 1, struct.pack("<I", 4))
    )
    return b"II*\x00\x08\x00\x00\x00" + struct.pack("<H", 3) + entries + b"\0" * 4 + b"data"


class ParserTests(unittest.TestCase):
    def test_jpeg_ignores_end_marker_inside_metadata(self):
        image = make_jpeg()
        source = io.BytesIO(image + b"suffix")
        self.assertEqual(recovery.parse_jpeg(source, 0, 1024), len(image))

    def test_png_size(self):
        image = make_png()
        source = io.BytesIO(b"prefix" + image + b"suffix")
        self.assertEqual(recovery.parse_png(source, 6, 1024), len(image))

    def test_bmp_size(self):
        image = make_bmp()
        source = io.BytesIO(image)
        self.assertEqual(recovery.parse_bmp(source, 0, 1024), len(image))

    def test_webp_size(self):
        payload = b"VP8 " + struct.pack("<I", 4) + b"data"
        image = b"RIFF" + struct.pack("<I", len(payload) + 4) + b"WEBP" + payload
        source = io.BytesIO(image)
        self.assertEqual(recovery.parse_webp(source, 0, 1024), len(image))

    def test_gif_size(self):
        image = make_gif()
        self.assertEqual(recovery.parse_gif(io.BytesIO(image), 0, 1024), len(image))

    def test_tiff_size(self):
        image = make_tiff()
        self.assertEqual(recovery.parse_tiff(io.BytesIO(image), 0, 1024), len(image))

    def test_detects_fat32_and_exfat(self):
        fat32 = bytearray(512)
        fat32[82:90] = b"FAT32   "
        exfat = bytearray(512)
        exfat[3:11] = b"EXFAT   "
        self.assertEqual(recovery.detect_filesystem(io.BytesIO(fat32)), "FAT32")
        self.assertEqual(recovery.detect_filesystem(io.BytesIO(exfat)), "exFAT")


class RecoveryTests(unittest.TestCase):
    def test_recovers_images_across_small_scan_chunks(self):
        png = make_png()
        bmp = make_bmp()
        disk = b"\x00" * 29 + png + b"\x00" * 37 + bmp + b"\x00" * 11

        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir)
            stats = recovery.recover(
                source=io.BytesIO(disk),
                output_dir=output,
                specs=[recovery.FORMATS["png"], recovery.FORMATS["bmp"]],
                chunk_size=16,
                max_file_size=1024,
                min_file_size=1,
                start_offset=0,
                scan_size=None,
                dry_run=False,
                keep_duplicates=False,
                quiet=True,
            )
            files = list(output.iterdir())
            self.assertEqual(stats.recovered, 2)
            self.assertEqual(len(files), 2)
            self.assertEqual({file.suffix for file in files}, {".png", ".bmp"})

    def test_deduplicates_identical_content(self):
        png = make_png()
        disk = b"\x00" * 10 + png + b"\x00" * 10 + png

        stats = recovery.recover(
            source=io.BytesIO(disk),
            output_dir=None,
            specs=[recovery.FORMATS["png"]],
            chunk_size=32,
            max_file_size=1024,
            min_file_size=1,
            start_offset=0,
            scan_size=None,
            dry_run=True,
            keep_duplicates=False,
            quiet=True,
        )
        self.assertEqual(stats.recovered, 1)
        self.assertEqual(stats.duplicates, 1)

    def test_cli_recovers_from_disk_image(self):
        png = make_png()
        png = png[:-12] + png_chunk(b"tEXt", bytes(range(256)) * 5) + png[-12:]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source_path = root / "usb.img"
            output_path = root / "output"
            source_path.write_bytes(b"\x00" * 101 + png + b"\x00" * 29)

            with contextlib.redirect_stdout(io.StringIO()):
                result = recovery.main(
                    [
                        str(source_path),
                        "--output",
                        str(output_path),
                        "--formats",
                        "png",
                        "--quiet",
                    ]
                )

            self.assertEqual(result, 0)
            recovered_files = list(output_path.glob("*.png"))
            self.assertEqual(len(recovered_files), 1)
            self.assertEqual(recovered_files[0].read_bytes(), png)


if __name__ == "__main__":
    unittest.main()
