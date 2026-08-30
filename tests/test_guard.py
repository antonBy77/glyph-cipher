from glyph_cipher.guard import audit, clean
from glyph_cipher.cli import encode


def test_clean_text():
    rep = audit("обычный текст без подвоха")
    assert rep["risk"] == "CLEAN"


def test_detects_zero_width():
    t = encode("тест", "extreme", seed=1)  # содержит zero-width маркер
    rep = audit(t)
    assert rep["risk"] == "HIGH"
    assert rep["zero_width"] >= 1


def test_clean_removes_all_hidden():
    t = encode("проверка связи ещё раз", "extreme", seed=3)
    cleaned = clean(t)
    rep2 = audit(cleaned)
    assert rep2["zero_width"] == 0 and rep2["tag_chars"] == 0 and rep2["bidi_overrides"] == 0


def test_detects_mixed_script():
    rep = audit("зайди на sitе.com сейчас")  # латинская 'site' с русской 'е'? используем честный пример
    # слова со смешением кириллица+латиница в одном токене
    rep = audit("акkаунт и passwоrd")
    assert "акkаунт" in rep["mixed_script_words"]


def test_tag_chars():
    rep = audit("ok\U000E0041\U000E0042")  # ASCII smuggling 'AB'
    assert rep["risk"] == "HIGH" and rep["tag_chars"] == 2
