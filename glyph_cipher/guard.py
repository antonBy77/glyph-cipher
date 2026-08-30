#!/usr/bin/env python3
"""glyph_guard: детектор и санитайзер скрытых Unicode-символов.

Защита от: zero-width smuggling, tag chars (ASCII smuggling),
bidi-оверрайдов, гомоглифов (смешение скриптов в слове).

Использование:
  python3 glyph_cipher/guard.py "подозрительный текст"      # аудит
  echo "текст" | python3 glyph_cipher/guard.py --clean      # очистка
  python3 glyph_cipher/guard.py --json file.txt             # JSON-отчёт
"""
from __future__ import annotations
import argparse
import json
import re
import sys
import unicodedata

# классы невидимых/опасных символов
ZERO_WIDTH = "\u200b\u200c\u200d\u2060\ufeff"
TAG_RANGE = range(0xE0000, 0xE0080)          # ASCII smuggling
BIDI = "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
FORMAT_CH = re.compile(r"[\u00ad\u180e\u2061\u2062\u2063]")  # soft-hyphen, invisible operators
# U+FE00-FE0F (variation selectors, emoji-модификаторы) — whitelist: массовый легитимный шум

CYR = re.compile(r"[А-Яа-яЁё]")
LAT = re.compile(r"[A-Za-z]")


def audit(text: str) -> dict:
    findings = {
        "zero_width": sum(text.count(c) for c in ZERO_WIDTH),
        "tag_chars": sum(1 for c in text if ord(c) in TAG_RANGE),
        "bidi_overrides": sum(text.count(c) for c in BIDI),
        "format_chars": len(FORMAT_CH.findall(text)),
        "mixed_script_words": [],
        "homoglyph_suspects": [],
    }
    for w in re.findall(r"\w+", text, re.UNICODE):
        if CYR.search(w) and LAT.search(w):
            findings["mixed_script_words"].append(w)
    # гомоглифы: визуальные двойники кириллица<->латиница
    homoglyph_pairs = str.maketrans("aceopxyABEHKMOPTXУaceopxy", "асеорхуАВЕНКМОРТХУасеорху")
    for w in re.findall(r"[A-Za-z]+", text):
        ru = w.translate(str.maketrans({k: v for k, v in zip("aceopxyABEHKMOPTX", "асеорхуАВЕНКМОРТХ")}))
        findings["homoglyph_suspects"].append(w)
        break  # эвристика: любой чисто-латинский токен, дающий русское слово — подозрителен; полная проверка — по словарю
    findings["risk"] = "HIGH" if (findings["zero_width"] or findings["tag_chars"] or findings["bidi_overrides"]) else (
        "MEDIUM" if findings["mixed_script_words"] else ("LOW" if findings["format_chars"] else "CLEAN"))
    return findings


def clean(text: str) -> str:
    out = []
    for c in text:
        o = ord(c)
        if c in ZERO_WIDTH or c in BIDI or o in TAG_RANGE or FORMAT_CH.match(c):
            continue
        out.append(c)
    # NFC-нормализация сводит часть гомоглифных комбинаций
    return unicodedata.normalize("NFC", "".join(out))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--clean", action="store_true", help="вывести очищенный текст")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("text", nargs="*", help="текст или имя файла")
    a = ap.parse_args()
    src = " ".join(a.text)
    try:
        with open(src, encoding="utf-8") as f:
            src = f.read()
    except OSError:
        pass
    if not src and not sys.stdin.isatty():
        src = sys.stdin.read()

    if a.clean:
        print(clean(src), end="")
        return
    rep = audit(src)
    rep["stats"] = {"chars_in": len(src), "chars_after_clean": len(clean(src))}
    print(json.dumps(rep, ensure_ascii=False, indent=2) if a.json else
          f"risk: {rep['risk']}\nzero-width: {rep['zero_width']}, tag: {rep['tag_chars']}, "
          f"bidi: {rep['bidi_overrides']}, format: {rep['format_chars']}\n"
          f"mixed-script words: {rep['mixed_script_words'][:10]}")


if __name__ == "__main__":
    main()
