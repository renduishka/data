"""Варіант 13. Рекурсивний сканер PII у текстових файлах."""

import ipaddress
import json
import logging
import os
import re
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)
PATTERNS = {
    "emails": re.compile(
        r"(?<![\w.+-])[A-Za-z0-9_.+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?![\w.-])"
    ),
    "cards": re.compile(
        r"(?<![\w+])(?:[0-9]{4}[- ]){3}[0-9]{4}(?!\w)|(?<![\w+])[0-9]{16}(?!\w)"
    ),
    "phones": re.compile(
        r"(?<![\w+])\+[0-9](?:[ -]?[0-9]){9,14}(?!\w)|(?<![\w.+-])0[0-9]{9}(?![\w.-])"
    ),
    "ips": re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])"),
}


@dataclass
class Finding:
    file: str
    line: int
    column: int
    type: str
    value: str


def mask_value(kind: str, value: str) -> str:
    """Маскує значення, не додаючи оригінал до звіту."""
    if kind == "emails":
        local, domain = value.rsplit("@", 1)
        return local[0] + "*" * max(1, len(local) - 1) + "@" + domain
    if kind == "ips":
        parts = value.split(".")
        return f"{parts[0]}.{parts[1]}.*.*"
    digit_positions = [i for i, ch in enumerate(value) if ch.isdigit()]
    visible = (
        set(digit_positions[:4] + digit_positions[-4:])
        if kind == "cards"
        else set(digit_positions[-4:])
    )
    return "".join(
        "*" if ch.isdigit() and i not in visible else ch for i, ch in enumerate(value)
    )


def find_in_line(text: str, selected: str):
    """Картки мають пріоритет над телефонами у разі перекриття."""
    card_spans = [m.span() for m in PATTERNS["cards"].finditer(text)]
    for kind, pattern in PATTERNS.items():
        if selected != "all" and kind != selected:
            continue
        for match in pattern.finditer(text):
            value = match.group()
            if kind == "phones" and any(
                match.start() < end and match.end() > start for start, end in card_spans
            ):
                continue
            if kind == "ips":
                try:
                    ipaddress.IPv4Address(value)
                except ipaddress.AddressValueError:
                    continue
            yield kind, match.start() + 1, value


def scan_directory(
    root: Path, selected: str = "all", mask: bool = False, output: Path | None = None
) -> dict:
    if selected not in ("all", "cards", "emails"):
        raise ValueError("Невідомий набір шаблонів")
    if not root.is_dir():
        raise ValueError("Каталог сканування не існує або недоступний")
    findings = []
    counts: Counter = Counter()
    scanned = skipped = 0

    # os.walk сумісний з Python 3.10; файли обробляються через pathlib.Path.
    def walk_error(error: OSError) -> None:
        raise error

    for directory, dirs, names in os.walk(root, onerror=walk_error, followlinks=False):
        dirs.sort()
        for name in sorted(names):
            path = Path(directory) / name
            if path.is_symlink() or (
                output is not None and path.resolve() == output.resolve()
            ):
                skipped += 1
                continue
            if not path.is_file():
                continue
            relative = path.relative_to(root).as_posix()
            # Невалідний UTF-8 / двійкові дані не аналізуються частково.
            try:
                text = path.read_text(encoding="utf-8-sig")
                if "\x00" in text:
                    raise UnicodeError("Binary file")
            except (OSError, UnicodeError):
                skipped += 1
                logger.warning("Пропущено нечитабельний або нетекстовий файл")
                continue
            scanned += 1
            file_count = 0
            for number, line in enumerate(text.splitlines(), 1):
                for kind, column, value in find_in_line(line, selected):
                    findings.append(
                        Finding(
                            relative,
                            number,
                            column,
                            kind,
                            mask_value(kind, value) if mask else value,
                        )
                    )
                    counts[kind] += 1
                    file_count += 1
            if file_count:
                # Значення PII не потрапляють у журнал навіть без --mask.
                logger.warning("Виявлено PII: %d збігів у текстовому файлі", file_count)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "patterns": selected,
        "masked": mask,
        "files_scanned": scanned,
        "files_skipped": skipped,
        "counts": {
            kind: counts[kind]
            for kind in PATTERNS
            if selected == "all" or kind == selected
        },
        "total_matches": sum(counts.values()),
        "findings": [asdict(finding) for finding in findings],
    }


def run_analysis(scan_dir: Path, patterns: str, mask: bool, out_json: Path) -> int:
    logging.basicConfig(
        level=logging.INFO, format="[%(levelname)s] %(message)s", force=True
    )
    try:
        root = scan_dir.resolve()
        output = out_json.resolve()
        if output == root or output in root.parents or root in output.parents:
            raise ValueError("Некоректний шлях вихідного файлу")
        logger.info("Розпочато сканування текстових файлів")
        report = scan_directory(root, patterns, mask, output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    except (OSError, ValueError):
        logger.error(
            "Сканування або запис звіту неможливі; перевірте шляхи й права доступу"
        )
        return 1
    print(
        f"Файлів перевірено: {report['files_scanned']}; пропущено: {report['files_skipped']}"
    )
    for kind, count in report["counts"].items():
        print(f"{kind}: {count}")
    print(f"Усього збігів: {report['total_matches']}")
    for item in report["findings"]:
        print(
            f"{item['file']}:{item['line']}:{item['column']} | {item['type']} | {item['value']}"
        )
    logger.info("JSON-звіт збережено")
    return 0
