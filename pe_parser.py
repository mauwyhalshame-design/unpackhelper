from dataclasses import dataclass
from pathlib import Path
import hashlib
import struct
from errors import AnalysisError


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int


@dataclass
class ImportLibrary:
    name: str
    functions: list[str]


@dataclass
class ExportSymbol:
    name: str | None
    ordinal: int
    rva: int


@dataclass
class PEInfo:
    path: str
    size: int
    sha256: str
    pe32_plus: bool
    machine: int
    machine_name: str
    number_of_sections: int
    entry_point_rva: int
    entry_point_section: str | None
    sections: list[Section]
    imports: list[ImportLibrary]
    exports: list[ExportSymbol]
    is_dotnet: bool
    data: bytes


def _u16(data, offset):
    if offset < 0 or offset + 2 > len(data):
        raise AnalysisError("الملف مبتور أو تالف")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data, offset):
    if offset < 0 or offset + 4 > len(data):
        raise AnalysisError("الملف مبتور أو تالف")
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data, offset):
    if offset < 0 or offset + 8 > len(data):
        raise AnalysisError("الملف مبتور أو تالف")
    return struct.unpack_from("<Q", data, offset)[0]


def _require_range(data, start, length, message="الملف مبتور أو تالف"):
    if start < 0 or length < 0 or start > len(data) or length > len(data) - start:
        raise AnalysisError(message)


_MACHINE_NAMES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "ARM",
    0x01C4: "ARM Thumb-2",
    0xAA64: "ARM64",
    0x0200: "Intel Itanium",
}


def _machine_name(machine):
    return _MACHINE_NAMES.get(machine, f"Unknown (0x{machine:04x})")


def _entry_point_section(entry_rva, sections):
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= entry_rva < section.virtual_address + span:
            return section.name or "<unnamed>"
    return None


def _rva_to_offset(data, sections, rva, header_size):
    """Convert an RVA to a raw file offset, or return None if unavailable."""
    if rva < header_size and rva < len(data):
        return rva
    for section in sections:
        span = max(section.virtual_size, section.raw_size)
        if section.virtual_address <= rva < section.virtual_address + span:
            relative = rva - section.virtual_address
            if relative >= section.raw_size:
                return None
            offset = section.raw_pointer + relative
            if offset < 0 or offset >= len(data):
                return None
            return offset
    return None


def _read_c_string(data, offset, limit=4096):
    if offset is None or offset < 0 or offset >= len(data):
        return None
    end = min(len(data), offset + limit)
    terminator = data.find(b"\0", offset, end)
    if terminator < 0:
        return None
    return data[offset:terminator].decode("ascii", errors="replace")


def _parse_imports(data, sections, directory_rva, directory_size, plus, header_size):
    if not directory_rva or not directory_size:
        return []
    descriptor_offset = _rva_to_offset(data, sections, directory_rva, header_size)
    if descriptor_offset is None:
        return []
    pointer_size = 8 if plus else 4
    ordinal_flag = 1 << (63 if plus else 31)
    imports = []
    max_descriptors = min(directory_size // 20 + 1, 4096)
    for index in range(max_descriptors):
        offset = descriptor_offset + index * 20
        if offset + 20 > len(data):
            break
        original_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, offset)
        if not (original_first_thunk or name_rva or first_thunk):
            break
        name_offset = _rva_to_offset(data, sections, name_rva, header_size)
        dll_name = _read_c_string(data, name_offset) or f"<unnamed DLL at 0x{name_rva:x}>"
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = _rva_to_offset(data, sections, thunk_rva, header_size)
        functions = []
        if thunk_offset is not None:
            for thunk_index in range(65536):
                item_offset = thunk_offset + thunk_index * pointer_size
                if item_offset + pointer_size > len(data):
                    break
                value = _u64(data, item_offset) if plus else _u32(data, item_offset)
                if value == 0:
                    break
                if value & ordinal_flag:
                    functions.append(f"ordinal:{value & 0xffff}")
                    continue
                hint_name_offset = _rva_to_offset(data, sections, value & (0x7fffffffffffffff if plus else 0x7fffffff), header_size)
                function = _read_c_string(data, hint_name_offset + 2) if hint_name_offset is not None else None
                functions.append(function or f"<unnamed import at 0x{value:x}>")
        imports.append(ImportLibrary(dll_name, functions))
    return imports


def _parse_exports(data, sections, directory_rva, directory_size, header_size):
    if not directory_rva or not directory_size:
        return []
    export_offset = _rva_to_offset(data, sections, directory_rva, header_size)
    if export_offset is None or export_offset + 40 > len(data):
        return []
    fields = struct.unpack_from("<IIHHIIIIIII", data, export_offset)
    _, _, _, _, _, ordinal_base, address_count, name_count, functions_rva, names_rva, ordinals_rva = fields
    functions_offset = _rva_to_offset(data, sections, functions_rva, header_size)
    names_offset = _rva_to_offset(data, sections, names_rva, header_size)
    ordinals_offset = _rva_to_offset(data, sections, ordinals_rva, header_size)
    if functions_offset is None:
        return []
    exports = []
    safe_function_count = min(address_count, 65536)
    function_rvas = []
    for index in range(safe_function_count):
        offset = functions_offset + index * 4
        if offset + 4 > len(data):
            break
        function_rvas.append(_u32(data, offset))
    names_by_ordinal = {}
    if names_offset is not None and ordinals_offset is not None:
        for index in range(min(name_count, 65536)):
            name_item = names_offset + index * 4
            ordinal_item = ordinals_offset + index * 2
            if name_item + 4 > len(data) or ordinal_item + 2 > len(data):
                break
            name_rva = _u32(data, name_item)
            ordinal_index = _u16(data, ordinal_item)
            name_offset = _rva_to_offset(data, sections, name_rva, header_size)
            name = _read_c_string(data, name_offset)
            if name is not None:
                names_by_ordinal[ordinal_index] = name
    for index, function_rva in enumerate(function_rvas):
        exports.append(ExportSymbol(names_by_ordinal.get(index), ordinal_base + index, function_rva))
    return exports


def parse_pe(path: Path, max_size=512 * 1024 * 1024) -> PEInfo:
    if not path.exists():
        raise AnalysisError(f"الملف غير موجود: {path}")
    if not path.is_file():
        raise AnalysisError(f"المسار ليس ملفًا: {path}")
    try:
        size = path.stat().st_size
        if size == 0:
            raise AnalysisError("الملف فارغ")
        if size > max_size:
            raise AnalysisError("الملف أكبر من الحد المسموح للتحليل")
        data = path.read_bytes()
    except PermissionError as exc:
        raise AnalysisError("لا توجد صلاحية لقراءة الملف") from exc
    except OSError as exc:
        raise AnalysisError(f"تعذر قراءة الملف: {exc}") from exc
    if data[:2] != b"MZ":
        raise AnalysisError("الملف ليس ملف PE صالحًا: ترويسة MZ غير موجودة")
    _require_range(data, 0x3C, 4)
    pe_offset = _u32(data, 0x3C)
    if pe_offset < 0x40:
        raise AnalysisError("الملف ليس ملف PE صالحًا: موقع ترويسة PE غير صحيح")
    _require_range(data, pe_offset, 4, "الملف مبتور أو تالف: ترويسة PE خارج الحدود")
    if data[pe_offset:pe_offset + 4] != b"PE\x00\x00":
        raise AnalysisError("الملف ليس ملف PE صالحًا: توقيع PE غير موجود")
    file_header = pe_offset + 4
    _require_range(data, file_header, 20, "الملف مبتور أو تالف: File Header غير مكتملة")
    machine = _u16(data, file_header)
    count = _u16(data, file_header + 2)
    optional_size = _u16(data, file_header + 16)
    optional = file_header + 20
    _require_range(data, optional, optional_size, "الملف مبتور أو تالف: Optional Header خارج الحدود")
    if optional_size < 20:
        raise AnalysisError("الملف ليس ملف PE صالحًا: Optional Header قصيرة جدًا")
    magic = _u16(data, optional)
    if magic not in (0x10B, 0x20B):
        raise AnalysisError("صيغة Optional Header غير مدعومة")
    plus = magic == 0x20B
    entry = _u32(data, optional + 16)
    header_size = _u32(data, optional + 60) if optional_size >= 64 else 0
    section_table = optional + optional_size
    sections = []
    for index in range(count):
        off = section_table + index * 40
        if off + 40 > len(data):
            raise AnalysisError("جدول الأقسام مبتور أو خارج حدود الملف")
        raw_name = data[off:off + 8].split(b"\0", 1)[0]
        virtual_size = _u32(data, off + 8)
        virtual_address = _u32(data, off + 12)
        raw_size = _u32(data, off + 16)
        raw_pointer = _u32(data, off + 20)
        characteristics = _u32(data, off + 36)
        if raw_size and (raw_pointer > len(data) or raw_size > len(data) - raw_pointer):
            raise AnalysisError(f"بيانات القسم خارج حدود الملف: {raw_name!r}")
        sections.append(Section(raw_name.decode("ascii", errors="replace").strip(), virtual_size, virtual_address, raw_size, raw_pointer, characteristics))
    directory = optional + (112 if plus else 96)
    directory_count_offset = optional + (108 if plus else 92)
    directory_count = _u32(data, directory_count_offset) if optional_size >= (112 if plus else 96) else 0
    export_rva = export_size = import_rva = import_size = 0
    if directory_count >= 1 and directory + 8 <= optional + optional_size:
        export_rva, export_size = struct.unpack_from("<II", data, directory)
    if directory_count >= 2 and directory + 16 <= optional + optional_size:
        import_rva, import_size = struct.unpack_from("<II", data, directory + 8)
    imports = _parse_imports(data, sections, import_rva, import_size, plus, header_size)
    exports = _parse_exports(data, sections, export_rva, export_size, header_size)
    is_dotnet = False
    if directory + 15 * 8 <= len(data):
        is_dotnet = bool(_u32(data, directory + 14 * 8) and _u32(data, directory + 14 * 8 + 4))
    return PEInfo(
        str(path),
        size,
        hashlib.sha256(data).hexdigest(),
        plus,
        machine,
        _machine_name(machine),
        count,
        entry,
        _entry_point_section(entry, sections),
        sections,
        imports,
        exports,
        is_dotnet,
        data,
    )
