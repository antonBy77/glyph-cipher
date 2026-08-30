#!/usr/bin/env python3
"""injection_scanner: чекер проекта на скрытые Unicode-инъекции.

Сканирует файлы (md, txt, py, js, json, yaml, yml, sh, toml) в дереве каталогов,
ищет: zero-width контрабанду, tag chars (ASCII smuggling), bidi-оверрайды,
format chars, смешение скриптов в словах, подозрительные паттерны промпт-инъекций.

Использование:
  python3 injection_scanner.py /path/to/project            # сводка
  python3 injection_scanner.py /path --json report.json    # полный отчёт
  python3 injection_scanner.py /path --deep                # + текстовые паттерны инъекций
"""
from __future__ import annotations
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from glyph_cipher.guard import audit  # noqa: E402

EXTS = {".md", ".txt", ".py", ".js", ".ts", ".json", ".yaml", ".yml", ".sh", ".toml", ".cfg", ".ini", ".html"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache", "dist", "build"}

# текстовые маркеры явных промпт-инъекций (для --deep)
INJECTION_PATTERNS = [
    (r"ignore (all|previous|above|prior) (instructions|prompts?)", "ignore-instructions"),
    (r"игнорир\w+ (все )?(предыдущ\w+|указани\w+|инструкци\w+)", "ignore-instructions-ru"),
    (r"(disregard|forget) (everything|the above|previous)", "disregard-context"),
    (r"system\s*prompt\s*[:=]", "system-prompt-leak"),
    (r"(reveal|print|show|output).{0,20}(system prompt|инструкци\w+)", "prompt-exfil"),
    (r"you are now (a|an|the) (dan|developer mode|jailbreak)", "role-hijack"),
    (r"</?(system|assistant|instructions?)>", "fake-tag"),
]
MAX_FILE = 2 * 1024 * 1024  # 2MB


def scan_file(path: str, deep: bool) -> dict | None:
    try:
        if os.path.getsize(path) > MAX_FILE:
            return {"file": path, "error": "too-large"}
        with open(path, encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        return {"file": path, "error": str(e)}
    rep = audit(text)
    findings = {k: v for k, v in rep.items()
                if k in ("zero_width", "tag_chars", "bidi_overrides", "format_chars") and v}
    words = rep.get("mixed_script_words") or []
    if words:
        findings["mixed_script_words"] = words[:20]
    if deep:
        hits = []
        for pat, tag in INJECTION_PATTERNS:
            for m in re.finditer(pat, text, re.I):
                line = text[:m.start()].count("\n") + 1
                hits.append({"line": line, "tag": tag, "match": m.group(0)[:80]})
        if hits:
            findings["injection_patterns"] = hits[:50]
    if findings:
        return {"file": path, "risk": rep["risk"], "findings": findings}
    return None


def scan_tree(root: str, deep: bool) -> tuple[list, int, int]:
    alerts, scanned, skipped = [], 0, 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".git")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.splitext(fn)[1].lower() not in EXTS:
                skipped += 1
                continue
            scanned += 1
            r = scan_file(p, deep)
            if r:
                alerts.append(r)
    return alerts, scanned, skipped


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root")
    ap.add_argument("--json", metavar="OUT")
    ap.add_argument("--deep", action="store_true", help="+ текстовые паттерны промпт-инъекций")
    a = ap.parse_args()
    alerts, scanned, skipped = scan_tree(a.root, a.deep)
    hi = [r for r in alerts if r.get("risk") == "HIGH"]
    print(f"scanned: {scanned} files (skipped {skipped} non-text) in {a.root}")
    print(f"alerts: {len(alerts)} | HIGH risk: {len(hi)}")
    for r in alerts:
        keys = {k: v for k, v in r.get("findings", {}).items() if k != "mixed_script_words"}
        mw = len(r.get("findings", {}).get("mixed_script_words", []))
        print(f"  [{r.get('risk','?')}] {r['file']}")
        for k, v in keys.items():
            print(f"      {k}: {v if not isinstance(v, list) else len(v)}")
        if mw:
            print(f"      mixed-script words: {mw} (напр. {r['findings']['mixed_script_words'][:3]})")
    if a.json:
        with open(a.json, "w", encoding="utf-8") as f:
            json.dump({"root": a.root, "scanned": scanned, "alerts": alerts}, f, ensure_ascii=False, indent=2)
        print(f"full report: {a.json}")


if __name__ == "__main__":
    main()
