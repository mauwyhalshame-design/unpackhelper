import json
from dataclasses import asdict
from assessment import assess_result
from entropy import entropy_label, shannon_entropy
from pe_parser import PEInfo
from fingerprint import Fingerprint


def _section_report(info: PEInfo) -> list[dict]:
    result = []
    for section in info.sections:
        start = section.raw_pointer
        end = min(start + section.raw_size, len(info.data))
        raw_available = section.raw_size > 0 and 0 <= start < len(info.data) and end > start
        raw = info.data[start:end] if raw_available else b""
        entropy = shannon_entropy(raw) if raw_available else None
        result.append({
            "name": section.name,
            "virtual_size": section.virtual_size,
            "virtual_address": f"0x{section.virtual_address:x}",
            "raw_size": section.raw_size,
            "raw_pointer": section.raw_pointer,
            "characteristics": f"0x{section.characteristics:08x}",
            "executable": bool(section.characteristics & 0x20000000),
            "writable": bool(section.characteristics & 0x80000000),
            "raw_data_available": raw_available,
            "entropy": round(entropy, 4) if entropy is not None else None,
            "entropy_label": entropy_label(entropy) if entropy is not None else "N/A",
        })
    return result


def build_result(info: PEInfo, detections: list[Fingerprint]) -> dict:
    top = detections[0] if detections else None
    sections = _section_report(info)
    high_entropy = [section["name"] for section in sections if section["entropy"] is not None and section["entropy"] >= 7.2]
    result = {
        "file": info.path,
        "size": info.size,
        "sha256": info.sha256,
        "format": "PE32+" if info.pe32_plus else "PE32",
        "machine": f"0x{info.machine:04x}",
        "architecture": info.machine_name,
        "entry_point_rva": f"0x{info.entry_point_rva:x}",
        "entry_point_section": info.entry_point_section,
        "imports": [{"dll": item.name, "functions": item.functions} for item in info.imports],
        "import_library_count": len(info.imports),
        "import_function_count": sum(len(item.functions) for item in info.imports),
        "exports": [{"name": item.name, "ordinal": item.ordinal, "rva": f"0x{item.rva:x}"} for item in info.exports],
        "export_count": len(info.exports),
        "sections": sections,
        "high_entropy_sections": high_entropy,
        "dotnet": info.is_dotnet,
        "likely_packer": top.name if top else "Unknown",
        "confidence": top.confidence if top else "None",
        "detections": [{"packer": item.name, "score": item.score, "confidence": item.confidence, "evidence": [asdict(e) for e in item.evidence]} for item in detections],
        "note": "Static fingerprint only; the file was not executed. High entropy can indicate compression or encryption, but is not proof of maliciousness.",
    }
    result["assessment"] = assess_result(result)
    return result


def render_text(result: dict) -> str:
    lines = [f"File: {result['file']}", f"Format: {result['format']}", f"Architecture: {result['architecture']}", f"SHA-256: {result['sha256']}", f"Sections: {len(result['sections'])}", f"Entry point: {result['entry_point_rva']} ({result['entry_point_section'] or 'unmapped'})", f".NET: {'yes' if result['dotnet'] else 'no'}", f"Likely packer: {result['likely_packer']}", f"Confidence: {result['confidence']}", f"Assessment: {result['assessment']['status']}"]
    lines.append(f"Assessment explanation: {result['assessment']['explanation']}")
    if result["assessment"]["reasons"]:
        lines.append("Assessment reasons: " + "; ".join(result["assessment"]["reasons"]))
    if result["assessment"]["warnings"]:
        lines.append("Assessment warnings: " + "; ".join(result["assessment"]["warnings"]))
    lines.append(f"Imports: {result['import_library_count']} DLL(s), {result['import_function_count']} function(s)")
    for library in result["imports"]:
        functions = ", ".join(library["functions"][:8]) or "none"
        suffix = " ..." if len(library["functions"]) > 8 else ""
        lines.append(f"  {library['dll']}: {functions}{suffix}")
    lines.append(f"Exports: {result['export_count']}")
    for symbol in result["exports"][:20]:
        lines.append(f"  {symbol['name'] or '<unnamed>'} (ordinal {symbol['ordinal']}, RVA {symbol['rva']})")
    if result["export_count"] > 20:
        lines.append("  ...")
    lines.append("Section analysis:")
    for section in result["sections"]:
        entropy = f"{section['entropy']:.4f} ({section['entropy_label']})" if section["entropy"] is not None else "N/A (raw data unavailable)"
        lines.append(f"  {section['name'] or '<unnamed>'}: entropy={entropy}, executable={section['executable']}, writable={section['writable']}")
    if result["detections"]:
        lines.append("Evidence:")
        for detection in result["detections"][:3]:
            lines.append(f"  {detection['packer']} ({detection['score']} points)")
            lines.extend(f"    - {item['description']} (+{item['points']}, {item['kind']})" for item in detection["evidence"])
    else:
        lines.append("Evidence: no known packer signature found")
    lines.append(f"High-entropy sections: {', '.join(result['high_entropy_sections']) or 'none'}")
    lines.append(f"Note: {result['note']}")
    return "\n".join(lines)


def render_json(result: dict) -> str:
    return json.dumps(result, indent=2, ensure_ascii=False)


def render_folder_text(result: dict) -> str:
    counts = result["counts"]
    lines = [
        f"Folder: {result['folder']}",
        f"Recursive: {'yes' if result['recursive'] else 'no'}",
        f"Total files: {result['total_files']}",
        f"PE files: {counts['PE']}",
        f"Non-PE files: {counts['Non-PE']}",
        f"Errors: {counts['Error']}",
        f"Skipped: {counts['Skipped']}",
        f"Files requiring review: {len(result['review_files'])}",
        f"Duplicate groups: {len(result['duplicate_groups'])}",
        "",
        "PE files:",
    ]
    if result["pe_files"]:
        for item in result["pe_files"]:
            detail = item["result"]
            lines.append(f"  [{detail['confidence']}] {item['path']} -> {detail['likely_packer']}")
            if detail["review_reasons"]:
                lines.append("    Review: " + "; ".join(detail["review_reasons"]))
    else:
        lines.append("  none")
    if result["review_files"]:
        lines.append("Review files:")
        lines.extend(f"  - {item['path']}: {'; '.join(item['reasons'])}" for item in result["review_files"])
    if result["errors"]:
        lines.append("Errors:")
        lines.extend(f"  - {item['path']}: {item['reason']}" for item in result["errors"])
    if result["skipped"]:
        lines.append("Skipped:")
        lines.extend(f"  - {item['path']}: {item['reason']}" for item in result["skipped"])
    return "\n".join(lines)


def render_compare_text(result: dict) -> str:
    status = "MATCH" if result["match"] else "DIFFERENT"
    return "\n".join([
        f"File 1: {result['file1']}",
        f"SHA-256: {result['sha256_1']}",
        f"File 2: {result['file2']}",
        f"SHA-256: {result['sha256_2']}",
        f"Content match: {status}",
        f"Note: {result['note']}",
    ])
