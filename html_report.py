from html import escape
from pathlib import Path


def render_html(result: dict) -> str:
    section_rows = []
    for item in result["sections"]:
        entropy = f"{item['entropy']:.4f}" if item["entropy"] is not None else "N/A"
        label = item["entropy_label"]
        status = "available" if item["raw_data_available"] else "raw data unavailable"
        section_rows.append(
            "<tr>"
            f"<td>{escape(str(item['name'] or '<unnamed>'))}</td>"
            f"<td>{entropy}</td>"
            f"<td>{escape(label)}</td>"
            f"<td>{escape(status)}</td>"
            f"<td>{'yes' if item['executable'] else 'no'}</td>"
            f"<td>{'yes' if item['writable'] else 'no'}</td>"
            f"<td>{item['raw_size']}</td>"
            "</tr>"
        )
    evidence = "".join(
        f"<li><strong>{escape(item['description'])}</strong> — +{item['points']} ({escape(item['kind'])})</li>"
        for detection in result["detections"][:3]
        for item in detection["evidence"]
    ) or "<li>No known packer signature found.</li>"
    high_entropy = ", ".join(escape(name) for name in result["high_entropy_sections"]) or "none"
    import_rows = "".join(
        f"<tr><td>{escape(item['dll'])}</td><td>{escape(', '.join(item['functions']) or 'none')}</td></tr>"
        for item in result["imports"]
    ) or '<tr><td colspan="2">No import directory found</td></tr>'
    export_rows = "".join(
        f"<tr><td>{escape(item['name'] or '<unnamed>')}</td><td>{item['ordinal']}</td><td>{escape(item['rva'])}</td></tr>"
        for item in result["exports"]
    ) or '<tr><td colspan="3">No exports found</td></tr>'
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>UnpackHelper Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#172033;margin:0;padding:32px}}
.card{{max-width:1150px;margin:auto;background:white;border-radius:14px;padding:28px;box-shadow:0 8px 30px #17203318}}
h1{{margin-top:0;color:#163b72}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:20px 0}}
.metric{{background:#eef4ff;border-left:4px solid #2c6bed;padding:12px;border-radius:8px}}.label{{font-size:12px;color:#52627a}}.value{{font-size:18px;font-weight:700;margin-top:4px;word-break:break-word}}
.verdict{{background:#eaf7ef;border-left:5px solid #229447;border-radius:8px;padding:16px;margin:18px 0}}.unknown{{background:#fff8df;border-left-color:#d78b00}}
table{{border-collapse:collapse;width:100%;margin-top:12px}}th,td{{border-bottom:1px solid #e5eaf2;padding:10px;text-align:left}}th{{background:#eef4ff}}
code{{background:#eef1f5;padding:2px 5px;border-radius:4px}}.note{{background:#fff8df;padding:14px;border-radius:8px;margin-top:20px}}
</style></head><body><main class="card"><h1>UnpackHelper Static Analysis Report</h1>
<div class="grid"><div class="metric"><div class="label">File</div><div class="value">{escape(result['file'])}</div></div>
<div class="metric"><div class="label">Likely packer</div><div class="value">{escape(result['likely_packer'])}</div></div>
<div class="metric"><div class="label">Confidence</div><div class="value">{escape(result['confidence'])}</div></div>
<div class="metric"><div class="label">Format</div><div class="value">{escape(result['format'])}</div></div>
	<div class="metric"><div class="label">Architecture</div><div class="value">{escape(result['architecture'])}</div></div>
	<div class="metric"><div class="label">Imports</div><div class="value">{result['import_library_count']} DLL / {result['import_function_count']} functions</div></div>
	<div class="metric"><div class="label">Exports</div><div class="value">{result['export_count']}</div></div></div>
<div class="verdict {'unknown' if result['likely_packer'] == 'Unknown' else ''}"><strong>Analysis summary:</strong> {escape(result['likely_packer'])} / {escape(result['confidence'])}.<br><span>No supported packer signature was found when the result is Unknown.</span></div>
<p><strong>SHA-256:</strong> <code>{escape(result['sha256'])}</code></p>
<h2>Evidence</h2><ul>{evidence}</ul>
<p><strong>High-entropy sections:</strong> {high_entropy}</p>
	<h2>Imports</h2><table><thead><tr><th>DLL</th><th>Functions</th></tr></thead><tbody>{import_rows}</tbody></table>
	<h2>Exports</h2><table><thead><tr><th>Name</th><th>Ordinal</th><th>RVA</th></tr></thead><tbody>{export_rows}</tbody></table>
	<h2>Section analysis</h2>
<table><thead><tr><th>Name</th><th>Entropy</th><th>Label</th><th>Raw data</th><th>Executable</th><th>Writable</th><th>Raw size</th></tr></thead><tbody>{''.join(section_rows)}</tbody></table>
<div class="note">{escape(result['note'])}</div>
</main></body></html>'''


def write_html(result: dict, path: Path) -> None:
    path.write_text(render_html(result), encoding="utf-8")


def write_folder_html(result: dict, path: Path) -> None:
    counts = result["counts"]
    rows = []
    for item in result["pe_files"]:
        detail = item["result"]
        reasons = "; ".join(detail["review_reasons"]) or "none"
        rows.append(
            "<tr>"
            f"<td>{escape(item['path'])}</td>"
            f"<td>{escape(detail['likely_packer'])}</td>"
            f"<td>{escape(detail['confidence'])}</td>"
            f"<td>{escape(reasons)}</td>"
            "</tr>"
        )
    errors = "".join(f"<li>{escape(item['path'])}: {escape(item['reason'])}</li>" for item in result["errors"]) or "<li>none</li>"
    skipped = "".join(f"<li>{escape(item['path'])}: {escape(item['reason'])}</li>" for item in result["skipped"]) or "<li>none</li>"
    duplicates = "".join("<li>" + "<br>".join(escape(item) for item in group) + "</li>" for group in result["duplicate_groups"]) or "<li>none</li>"
    html = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>UnpackHelper Folder Report</title>
<style>body{{font-family:Segoe UI,Arial,sans-serif;background:#f4f7fb;color:#172033;margin:0;padding:32px}}.card{{max-width:1200px;margin:auto;background:white;border-radius:14px;padding:28px;box-shadow:0 8px 30px #17203318}}h1{{color:#163b72}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}}.metric{{background:#eef4ff;border-left:4px solid #2c6bed;padding:12px;border-radius:8px}}.label{{font-size:12px;color:#52627a}}.value{{font-size:20px;font-weight:700}}table{{border-collapse:collapse;width:100%}}th,td{{border-bottom:1px solid #e5eaf2;padding:10px;text-align:left;vertical-align:top}}th{{background:#eef4ff}}section{{margin-top:24px}}li{{margin:6px 0}}</style></head><body><main class="card"><h1>UnpackHelper Folder Report</h1><p><strong>Folder:</strong> {escape(result['folder'])}<br><strong>Recursive:</strong> {'yes' if result['recursive'] else 'no'}</p><div class="grid"><div class="metric"><div class="label">Total files</div><div class="value">{result['total_files']}</div></div><div class="metric"><div class="label">PE files</div><div class="value">{counts['PE']}</div></div><div class="metric"><div class="label">Non-PE</div><div class="value">{counts['Non-PE']}</div></div><div class="metric"><div class="label">Errors</div><div class="value">{counts['Error']}</div></div><div class="metric"><div class="label">Review</div><div class="value">{len(result['review_files'])}</div></div></div><section><h2>PE files</h2><table><thead><tr><th>Path</th><th>Packer</th><th>Confidence</th><th>Review reasons</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan="4">No PE files found</td></tr>'}</tbody></table></section><section><h2>Errors</h2><ul>{errors}</ul></section><section><h2>Skipped</h2><ul>{skipped}</ul></section><section><h2>Duplicate SHA-256 groups</h2><ul>{duplicates}</ul></section></main></body></html>'''
    path.write_text(html, encoding="utf-8")
