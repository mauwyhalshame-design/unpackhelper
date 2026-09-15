from typing import Any


def assess_result(result: dict[str, Any]) -> dict[str, Any]:
    reasons: list[str] = []
    warnings: list[str] = []
    if result["likely_packer"] != "Unknown":
        reasons.append(f"known packer detected: {result['likely_packer']}")
    if result["high_entropy_sections"]:
        reasons.append("very high entropy sections: " + ", ".join(result["high_entropy_sections"]))
    standard = {".text", ".itext", ".data", ".bss", ".idata", ".tls", ".rdata", ".rsrc", ".reloc", ".debug", ".pdata"}
    custom = [section["name"] for section in result["sections"] if section["name"] and section["name"].lower() not in standard]
    if custom:
        warnings.append("custom sections: " + ", ".join(custom))
    rwx = [section["name"] for section in result["sections"] if section["executable"] and section["writable"]]
    if rwx:
        reasons.append("sections are both executable and writable: " + ", ".join(rwx))
    if custom and any(section["entropy"] is not None and section["entropy"] >= 7.2 for section in result["sections"] if section["name"] in custom):
        reasons.append("custom section with very high entropy")
    if not reasons:
        status = "OK"
        explanation = "No strong review indicator matched the configured rules. This is not a safety verdict."
    else:
        status = "REVIEW_REQUIRED"
        explanation = "One or more static indicators require analyst review; this is not proof of malware."
    return {"status": status, "reasons": reasons, "warnings": warnings, "explanation": explanation}
