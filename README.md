# glyph-cipher

Набор для обфускации текста и защиты от скрытых Unicode-атак. Два инструмента: «меч» (обфускатор) и «щит» (детектор/санитайзер + чекер проекта).

## 1. glyph-cipher: обфускация текста (меч)

Основан на эффекте «кембриджского университета» (typoglycemia) + leet + гомоглифы + невидимые Unicode-символы. Человек (и сильный LLM с контекстом) читает, а классические парсеры, регулярки и AI-детекторы — спотыкаются.

| Уровень | Приёмы | Человек читает | Токенизатор LLM |
|---|---|---|---|
| `light` | перемешивание средних букв слов | легко | почти нормально |
| `hard` | + leet (е→3, о→0, а→4, т→7) | медленно, но ок | ломается на мусорных токенах |
| `extreme` | + Unicode-гомоглифы + zero-width разделители | ребус | полный распад токенизации |

```bash
python3 glyph_cipher/cli.py demo                          # пример всех уровней
python3 glyph_cipher/cli.py encode -l hard -s 42 "текст"  # зашифровать
echo "<шифр>" | python3 glyph_cipher/cli.py decode        # расшифровать (маркер уровня = zero-width пара)
python3 -m pytest tests/ -q                               # 10 passed
```

Seed делает shuffle детерминированным. Маркер уровня зашит парой zero-width символов — decode сам определяет уровень.

## 2. guard.py: детектор и санитайзер скрытых символов (щит)

Ловит на входе: zero-width (U+200B–D, U+2060, U+FEFF), Unicode tag chars (U+E0000+, ASCII smuggling), bidi-оверрайды, format chars, смешение кириллицы+латиницы в одном слове (маркер гомоглиф-атаки). U+FE00–FE0F (emoji-вариации) — в whitelist: легитимный шум.

Вердикты: CLEAN / LOW / MEDIUM / HIGH.

```bash
echo "текст" | python3 glyph_cipher/guard.py --clean > safe.txt   # вырезать всё скрытое + NFC
python3 glyph_cipher/guard.py --json "подозрительный текст"        # JSON-отчёт
```

## 3. injection_scanner.py: чекер проекта на инъекции

Сканирует дерево каталогов (md/py/js/json/yaml/sh/toml...) на скрытые Unicode-символы, а с `--deep` — и на текстовые паттерны промпт-инъекций («ignore previous instructions» / RU-варианты, exfil системного промпта, fake `<system>`-теги).

```bash
python3 glyph_cipher/injection_scanner.py /path/to/project            # сводка
python3 glyph_cipher/injection_scanner.py /path --json report.json   # полный отчёт
python3 glyph_cipher/injection_scanner.py /path --deep                # + текстовые паттерны
```

Рекомендуемое применение: вход LLM-агентов и RAG-индексации (иначе скрытые инструкции лягут в память), email-триаж, периодический аудит скиллов/инструкций (см. cron-скрипт-пример ниже).

Тихий сторож для cron (молчит при чистом результате, алерт при HIGH):

```python
# ~/.hermes/scripts/injection_check.py — обёртка scan_tree() по нужным каталогам
```

## Исследовательская база

- Creo et al. 2025, «Evading AI-Generated Text Detectors using Homoglyphs» (ACL GenAIDetect)
- promptfoo red-team strategy «Leetspeak»
- Invisible Unicode / ASCII smuggling: Trend Micro, Keysight, Cloud Security Alliance (2026)

## Границы применения

Обфускатор — НЕ криптография: восстановление возможно человеком и сильным LLM по контексту. Защищает только от массового автоматического сканирования/индексации и годится для стресс-тестов собственных парсеров и модерации. Детектор снижает, но не исключает риск: смешанные скрипты и семантические инъекции без спецсимволов требуют отдельного анализа.
