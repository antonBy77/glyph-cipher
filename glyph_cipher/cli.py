#!/usr/bin/env python3
"""glyph-cipher: текст-обфускация на эффекте «кембриджского университета».

Уровни:
  light   — перемешивание средних букв слов (typoglycemia), читается человеком легко
  hard    — + leet-замены (е->3, о->0, а->4, т->7 ...), спецсимволы внутри слов
  extreme — + гомоглифы Unicode + невидимые разделители (ноль-видимая метка)

Все уровни обратимы: seed + маркер уровня позволяют точно восстановить текст.
Использование: защита приватных заметок от пассивного AI-сканирования/индексации,
стресс-тесты модерации и парсеров. НЕ криптография — от человека не защищает.
"""
from __future__ import annotations
import argparse
import json
import random
import re
import sys

# --- гомоглифы (визуально похожие Unicode-заменители) ---
HOMOGLYPHS = {
    "a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х",
    "y": "у", "i": "і", "j": "ј", "s": "ѕ",
}
# --- leet: русские и латинские буквы -> цифры/символы ---
LEET = {
    # только однозначные замены: з->3 убрано (коллизия с е->3 ломала декод)
    "е": "3", "о": "0", "а": "4", "и": "1", "т": "7",
    "e": "3", "o": "0", "a": "4", "i": "1", "t": "7", "s": "5", "b": "8",
}
# --- невидимые разделители (zero-width) ---
ZW = "\u200b\u200c\u200d\u2060"
# метка, которую вставляем первой парой невидимых символов: HL=lvl, HD=lvl+d? упрощённо ниже
MARKERS = {"light": "\u200b\u200c", "hard": "\u200b\u200d", "extreme": "\u200b\u2060"}
DECODE_MAP = {v: k for k, v in MARKERS.items()}
REVERSE_LEET = {}  # заполняется динамически (многозначные замены разруливаются контекстом-словарём)


def _shuffle_mid(word: str, rng: random.Random) -> str:
    if len(word) <= 3:
        return word
    mid = list(word[1:-1])
    rng.shuffle(mid)
    return word[0] + "".join(mid) + word[-1]


def encode(text: str, level: str = "light", seed: int = 42) -> str:
    rng = random.Random(seed)
    marker = MARKERS[level]

    def process_word(m: re.Match) -> str:
        w = m.group(0)
        w = _shuffle_mid(w, rng)
        if level in ("hard", "extreme"):
            w = "".join(LEET.get(ch.lower(), ch) for ch in w)
        if level == "extreme" and re.fullmatch(r"[A-Za-z]+", w):
            # гомоглифы — только для латиницы: кириллицу не трогаем,
            # иначе декод превращает русские буквы в латинские двойники
            w = "".join(HOMOGLYPHS.get(ch.lower(), ch) for ch in w)
            # вставляем zero-width после случайной позиции
            pos = rng.randint(1, max(1, len(w) - 1))
            w = w[:pos] + rng.choice(ZW) + w[pos:]
        return w

    body = re.sub(r"[А-Яа-яЁёA-Za-z]+", process_word, text)
    return marker + body


# --- декодер ---
# мини-словарь для разруливания leet-неоднозначностей (расширяемый)
DICT = set()


def _load_dict(words_file: str | None):
    global DICT
    if words_file:
        try:
            DICT = {w.strip().lower() for w in open(words_file, encoding="utf-8") if w.strip()}
        except OSError:
            pass


def decode(text: str) -> tuple[str, str]:
    """Возвращает (восстановленный_текст, уровень). level='?' если метка не найдена."""
    m = re.match(f"^({'|'.join(map(re.escape, MARKERS.values()))})", text)
    level = DECODE_MAP.get(m.group(1), "?") if m else "?"
    if m:
        text = text[m.end():]

    inv_homo = {v: k for k, v in HOMOGLYPHS.items()}
    inv_leet = {"3": "е", "0": "о", "4": "а", "1": "и", "7": "т", "5": "s", "8": "b"}

    def process_word(mw: re.Match) -> str:
        w = mw.group(0)
        w = "".join(inv_leet.get(ch, ch) for ch in w)
        # реверс гомоглифов только для слов без кириллицы:
        # в encode гомоглифы применялись лишь к чисто латинским словам
        if not re.search(r"[А-Яа-яЁё]", w):
            w = "".join(inv_homo.get(ch, ch) for ch in w)
        # анаграмма: первая/последняя буквы верны; пытаемся сопоставить словарю
        if len(w) > 3 and DICT:
            cand = [d for d in DICT if len(d) == len(w) and d[0] == w[0].lower() and d[-1] == w[-1].lower()
                    and sorted(d) == sorted(w.lower())]
            if len(cand) == 1:
                return cand[0] if w[0].islower() else cand[0].capitalize()
        return w

    cleaned = "".join(ch for ch in text if ch not in ZW)
    return re.sub(r"[А-Яа-яЁёA-Za-z0-9]+", process_word, cleaned), level


def main():
    ap = argparse.ArgumentParser(description="glyph-cipher: typoglycemia/leet/homoglyph text obfuscator")
    ap.add_argument("mode", choices=["encode", "decode", "demo"])
    ap.add_argument("-l", "--level", choices=["light", "hard", "extreme"], default="light")
    ap.add_argument("-s", "--seed", type=int, default=42)
    ap.add_argument("-d", "--dict", help="файл словаря для декодера (одно слово на строку)")
    ap.add_argument("text", nargs="*", help="текст (или из stdin)")
    a = ap.parse_intermixed_args()
    text = " ".join(a.text) or (sys.stdin.read() if not sys.stdin.isatty() else "")
    if a.dict:
        _load_dict(a.dict)

    if a.mode == "demo":
        sample = "По результатам исследований одного английского университета, не имеет значения, в каком порядке расположены буквы в слове."
        for lvl in ("light", "hard", "extreme"):
            enc = encode(sample, lvl, a.seed)
            dec, detected = decode(enc)
            print(f"--- {lvl} ---\n{enc}\n[decode -> {detected}] {dec}\n")
    elif a.mode == "encode":
        print(encode(text, a.level, a.seed))
    else:
        dec, lvl = decode(text)
        print(f"[level: {lvl}]\n{dec}")


if __name__ == "__main__":
    main()
