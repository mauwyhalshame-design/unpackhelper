import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from errors import AnalysisError
from fingerprint import fingerprint
from pe_parser import parse_pe
from report import build_result


def make_test_pe(path: Path) -> None:
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    file_header = 0x84
    struct.pack_into("<H", data, file_header, 0x14C)
    struct.pack_into("<H", data, file_header + 2, 2)
    struct.pack_into("<H", data, file_header + 16, 0xE0)
    optional = file_header + 20
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    section_table = optional + 0xE0
    for index, name in enumerate((b"UPX0", b"UPX1")):
        off = section_table + index * 40
        data[off:off + len(name)] = name
        struct.pack_into("<I", data, off + 8, 0x1000)
        struct.pack_into("<I", data, off + 12, 0x1000 + index * 0x1000)
        struct.pack_into("<I", data, off + 16, 0x80)
        struct.pack_into("<I", data, off + 20, 0x200 + index * 0x80)
        struct.pack_into("<I", data, off + 36, 0x60000020)
    data[0x250:0x254] = b"UPX!"
    path.write_bytes(data)


def make_import_export_pe(path: Path) -> None:
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    file_header = 0x84
    struct.pack_into("<H", data, file_header, 0x14C)
    struct.pack_into("<H", data, file_header + 2, 1)
    struct.pack_into("<H", data, file_header + 16, 0xE0)
    optional = file_header + 20
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96, 0x11A0, 40)
    struct.pack_into("<II", data, optional + 104, 0x1100, 40)
    section_table = optional + 0xE0
    data[section_table:section_table + 6] = b".rdata"
    struct.pack_into("<I", data, section_table + 8, 0x600)
    struct.pack_into("<I", data, section_table + 12, 0x1000)
    struct.pack_into("<I", data, section_table + 16, 0x600)
    struct.pack_into("<I", data, section_table + 20, 0x200)
    struct.pack_into("<I", data, section_table + 36, 0x40000040)
    struct.pack_into("<IIIII", data, 0x300, 0x1140, 0, 0, 0x1160, 0x1140)
    struct.pack_into("<II", data, 0x340, 0x1170, 0)
    data[0x360:0x360 + 13] = b"KERNEL32.dll\0"
    struct.pack_into("<H", data, 0x370, 0)
    data[0x372:0x372 + 12] = b"CreateFileA\0"
    struct.pack_into("<IIHHIIIIIII", data, 0x3A0, 0, 0, 0, 0, 0, 1, 1, 1, 0x11D0, 0x11D4, 0x11D8)
    struct.pack_into("<I", data, 0x3D0, 0x1000)
    struct.pack_into("<I", data, 0x3D4, 0x11E0)
    struct.pack_into("<H", data, 0x3D8, 0)
    data[0x3E0:0x3E0 + 12] = b"DllFunction\0"
    path.write_bytes(data)

def make_pe32_plus_import_pe(path: Path) -> None:
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    file_header = 0x84
    struct.pack_into("<H", data, file_header, 0x8664)
    struct.pack_into("<H", data, file_header + 2, 1)
    struct.pack_into("<H", data, file_header + 16, 0xF0)
    optional = file_header + 20
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 108, 16)
    struct.pack_into("<II", data, optional + 120, 0x1100, 40)
    section_table = optional + 0xF0
    data[section_table:section_table + 6] = b".idata"
    struct.pack_into("<I", data, section_table + 8, 0x600)
    struct.pack_into("<I", data, section_table + 12, 0x1000)
    struct.pack_into("<I", data, section_table + 16, 0x600)
    struct.pack_into("<I", data, section_table + 20, 0x200)
    struct.pack_into("<I", data, section_table + 36, 0xC0000040)
    struct.pack_into("<IIIII", data, 0x300, 0x1140, 0, 0, 0x1160, 0x1148)
    struct.pack_into("<QQ", data, 0x340, 0x1170, 0)
    data[0x360:0x360 + len(b"USER32.dll\0")] = b"USER32.dll\0"
    struct.pack_into("<H", data, 0x370, 0)
    data[0x372:0x372 + len(b"WideCall\0")] = b"WideCall\0"
    path.write_bytes(data)


class TestProject(unittest.TestCase):
    def test_upx_detection_and_score(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.exe"
            make_test_pe(path)
            info = parse_pe(path)
            self.assertEqual(info.machine_name, "x86")
            self.assertEqual(info.entry_point_section, "UPX0")
            detections = fingerprint(info)
            self.assertEqual(detections[0].name, "UPX")
            self.assertGreaterEqual(detections[0].score, 90)
            self.assertEqual(detections[0].confidence, "High")

    def test_imports_and_exports_are_parsed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "imports-exports.exe"
            make_import_export_pe(path)
            info = parse_pe(path)
            self.assertEqual(len(info.imports), 1)
            self.assertEqual(info.imports[0].name, "KERNEL32.dll")
            self.assertEqual(info.imports[0].functions, ["CreateFileA"])
            self.assertEqual(len(info.exports), 1)
            self.assertEqual(info.exports[0].name, "DllFunction")
            self.assertEqual(info.exports[0].ordinal, 1)

    def test_pe32_plus_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "x64-sample.exe"
            make_pe32_plus_import_pe(path)
            info = parse_pe(path)
            self.assertTrue(info.pe32_plus)
            self.assertEqual(info.machine_name, "x64")
            self.assertEqual(info.imports[0].name, "USER32.dll")
            self.assertEqual(info.imports[0].functions, ["WideCall"])

    def test_rejects_non_pe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.bin"
            path.write_bytes(b"not a PE")
            with self.assertRaises(AnalysisError):
                parse_pe(path)

    def test_rejects_missing_file(self):
        with self.assertRaises(AnalysisError):
            parse_pe(Path("missing-file.exe"))

    def test_marker_alone_is_not_high(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "marker-only.exe"
            make_test_pe(path)
            data = bytearray(path.read_bytes())
            data[data.find(b"UPX0"):data.find(b"UPX0") + 4] = b"CODE"
            data[data.find(b"UPX1"):data.find(b"UPX1") + 4] = b"DATA"
            path.write_bytes(data)
            detections = fingerprint(parse_pe(path))
            self.assertEqual(detections[0].name, "UPX")
            self.assertEqual(detections[0].confidence, "Medium")

    def test_config_validation(self):
        from config import load_config
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text('{"max_file_size": 1024}', encoding="utf-8")
            self.assertEqual(load_config(str(path))["max_file_size"], 1024)
            path.write_text('{"max_file_size": -1}', encoding="utf-8")
            with self.assertRaises(AnalysisError):
                load_config(str(path))

    def test_report_contains_identity_and_evidence(self):
        from report import build_result, render_json, render_text
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report-sample.exe"
            make_test_pe(path)
            info = parse_pe(path)
            result = build_result(info, fingerprint(info))
            self.assertEqual(result["likely_packer"], "UPX")
            self.assertEqual(len(result["sha256"]), 64)
            self.assertEqual(result["imports"], [])
            self.assertEqual(result["exports"], [])
            self.assertIn("Imports: 0 DLL(s), 0 function(s)", render_text(result))
            self.assertIn("Exports: 0", render_text(result))
            self.assertIn("Evidence:", render_text(result))
            self.assertIn('"likely_packer": "UPX"', render_json(result))

    def test_entropy_and_html_report(self):
        from entropy import entropy_label, shannon_entropy
        from html_report import render_html
        from report import build_result
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertEqual(entropy_label(0.0), "Low")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "html-sample.exe"
            make_test_pe(path)
            info = parse_pe(path)
            result = build_result(info, fingerprint(info))
            html = render_html(result)
            self.assertIn("UnpackHelper Static Analysis Report", html)
            self.assertIn("Entropy", html)
            self.assertIn("Imports", html)
            self.assertIn("Exports", html)
            self.assertIn("UPX", html)

    def test_folder_scan_classifies_and_groups_files(self):
        from folder_scan import scan_folder
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pe_path = root / "sample.exe"
            copy_path = root / "copy.bin"
            text_path = root / "notes.txt"
            nested = root / "nested"
            nested.mkdir()
            make_test_pe(pe_path)
            copy_path.write_bytes(pe_path.read_bytes())
            text_path.write_text("not a PE", encoding="utf-8")
            result = scan_folder(root, max_size=1024 * 1024, recursive=True)
            self.assertEqual(result["counts"]["PE"], 2)
            self.assertEqual(result["counts"]["Non-PE"], 1)
            self.assertEqual(len(result["duplicate_groups"]), 1)

    def test_compare_files_by_sha256(self):
        from compare import compare_files
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.bin"
            second = root / "second.bin"
            first.write_bytes(b"same content")
            second.write_bytes(b"same content")
            result = compare_files(first, second)
            self.assertTrue(result["match"])
            second.write_bytes(b"different content")
            self.assertFalse(compare_files(first, second)["match"])

    def test_extended_signature_catalog(self):
        from signatures import SIGNATURES
        self.assertIn("NsPack", SIGNATURES)
        self.assertIn("Petite", SIGNATURES)
        self.assertIn("RLPack", SIGNATURES)
        self.assertIn("WWPack", SIGNATURES)

    def test_assessment_exposes_review_status(self):
        from assessment import assess_result
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "assessment-sample.exe"
            make_test_pe(path)
            info = parse_pe(path)
            result = build_result(info, fingerprint(info))
            self.assertEqual(result["assessment"]["status"], "REVIEW_REQUIRED")
            self.assertTrue(result["assessment"]["reasons"])

if __name__ == "__main__":
    unittest.main()
