from glyph_cipher.cli import encode, decode, _load_dict

SAMPLE = "Результаты исследования показывают порядок букв"
DICT_WORDS = ["результаты", "исследования", "показывают", "порядок", "букв"]


def test_light_roundtrip_shape():
    enc = encode(SAMPLE, "light", seed=1)
    dec, lvl = decode(enc)
    assert lvl == "light"
    # light: без leet — после деанаграммирования символы совпадают
    assert enc != SAMPLE
    assert dec.replace(" ", "") != ""


def test_marker_detection():
    for lvl in ("light", "hard", "extreme"):
        enc = encode("тест", lvl, seed=7)
        _, detected = decode(enc)
        assert detected == lvl


def test_extreme_removes_invisible():
    enc = encode("проверка связи", "extreme", seed=3)
    dec, _ = decode(enc)
    assert not any(ch in "\u200b\u200c\u200d\u2060" for ch in dec)


def test_word_lengths_preserved():
    enc = encode(SAMPLE, "hard", seed=5)
    # спецсимволы внутрь слов не вставляем (только leet-цифры) — длина слов сохранена
    import re
    for orig, enc_w in zip(SAMPLE.split(), re.sub(r"[^\w\s]", " ", enc).split()):
        assert len(orig) == len(enc_w)


def test_dict_decode_recovers_words():
    import tempfile, os
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write("\n".join(DICT_WORDS))
        path = f.name
    _load_dict(path)
    enc = encode(SAMPLE, "light", seed=2)
    dec, _ = decode(enc)
    for w in DICT_WORDS:
        assert w in dec.lower(), f"{w} not recovered from: {dec}"
    os.unlink(path)
