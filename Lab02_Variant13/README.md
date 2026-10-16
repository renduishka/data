# Лабораторна робота 2 Варіант 13

Лозинский Р.Р., КБ-202.

- `Звіт_ЛР2_Варіант13_Лозинский.docx` — звіт за наданим зразком.
- `labs/lab02/README.md` — повні інструкції, алгоритм та обмеження.
- `labs/lab02/` — модулі main.py, task1.py, task2.py і навчальні дані.
- `shared/student.py` — номер варіанта й дані студента.
- `tests/test_lab02.py` — 8 автоматизованих перевірок.
- `results/` — три масковані JSON-звіти, виведення програм, результати тестів і Ruff.

Швидкий запуск із цієї папки у Python 3.10+:

```sh
python -m labs.lab02.main demo
python -m labs.lab02.main analyze --scan-dir labs/lab02/data/data_v13/scan --patterns all --mask --out-json results/pii_all.json
python -m unittest discover -s tests -v
```

У звіті залишено два поля для URL вашого репозиторію ЛР1 і хешу фактичного
коміту. Git-репозиторій не створювався й код не публікувався. Інструкцію
перенесення до репозиторію ЛР1 наведено в labs/lab02/README.md.
