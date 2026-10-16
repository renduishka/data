"""Команди demo та analyze. Запускати з кореня проєкту."""

import argparse
from datetime import timedelta
from pathlib import Path

from labs.lab02.task1 import SESSION_TIMEOUT_SEC, Admin, User, UserAccount
from labs.lab02.task2 import run_analysis
from shared.student import VARIANT_NUMBER


def run_demo() -> None:
    print(f"Лабораторна робота 2 | Варіант {VARIANT_NUMBER} | Завдання 1")
    user = User("student13", "student13@example.test")
    user.set_password("TrainingPassword13!")
    account = UserAccount(user)
    print(user)
    account["email"] = "student_new@example.test"
    print("Новий email:", account["email"])
    try:
        account["email"] = "invalid"
    except ValueError:
        print("Некоректний email відхилено")
    print("Невдалий вхід:", account.login("student13", "wrong", "192.0.2.13"))
    print(
        "Успішний вхід:",
        account.login("student13", "TrainingPassword13!", "192.0.2.13"),
    )
    print("Сеанс активний:", account.is_authenticated())
    # Імітація минулої активності без очікування 15 хвилин.
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print("Сеанс після таймауту:", account.is_authenticated())
    admin = Admin("admin13", "admin13@example.test", {"READ_LOGS"})
    admin.grant_permission("SCAN_PII")
    print(admin)
    print("Право SCAN_PII:", admin.has_permission("SCAN_PII"))
    admin.revoke_permission("SCAN_PII")
    print("Право після відкликання:", admin.has_permission("SCAN_PII"))
    for key in ("password_hash", "unknown"):
        try:
            account[key]
        except KeyError:
            print(f"Доступ до ключа {key} відхилено")
    try:
        account["active"] = "yes"
    except TypeError:
        print("Неправильний тип active відхилено")
    account.login("student13", "TrainingPassword13!", "192.0.2.13")
    account.logout()
    print("Після logout:", account.is_authenticated())
    user.deactivate()
    print(
        "Вхід неактивного користувача:",
        account.login("student13", "TrainingPassword13!", "192.0.2.13"),
    )
    print("Журнал аудиту")
    account.audit_log.show_all()


def main() -> int:
    parser = argparse.ArgumentParser(description="ЛР2 Варіант 13 Сканер PII")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="Модель користувачів і сеансів")
    analyze = commands.add_parser("analyze", help="Пошук відкритих PII")
    analyze.add_argument("--scan-dir", type=Path, required=True)
    analyze.add_argument(
        "--patterns", choices=("all", "cards", "emails"), default="all"
    )
    analyze.add_argument("--mask", action="store_true", help="Маскувати консоль і JSON")
    analyze.add_argument("--out-json", type=Path, required=True)
    args = parser.parse_args()
    if args.command == "demo":
        run_demo()
        return 0
    return run_analysis(args.scan_dir, args.patterns, args.mask, args.out_json)


if __name__ == "__main__":
    raise SystemExit(main())
