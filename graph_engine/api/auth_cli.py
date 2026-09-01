"""CLI di gestione utenti della dashboard — ``python -m graph_engine.api.auth_cli``.

Opera sullo stesso SQLite dell'API (default ``data/graph_engine.db``):
per il container Docker eseguirla dall'interno::

    docker compose exec ivx-graph-engine python -m graph_engine.api.auth_cli list

Comandi::

    list                     elenca gli utenti (username e ruolo)
    add USER [--role ...]    crea un utente (password chiesta in modo sicuro
                             con getpass, o via --password per gli script)
    delete USER              cancella un utente (revoca le sue sessioni)
    passwd USER              reimposta la password (revoca le sessioni)
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from graph_engine.api import auth
from graph_engine.storage.schema import DEFAULT_DB_PATH


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m graph_engine.api.auth_cli",
        description="Gestione utenti della dashboard IVX-GraphEngine.",
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB_PATH,
        help=f"Percorso del database SQLite (default: {DEFAULT_DB_PATH})",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="elenca gli utenti")

    p_add = sub.add_parser("add", help="crea un utente")
    p_add.add_argument("user")
    p_add.add_argument(
        "--role", choices=("admin", "operator"), default="operator"
    )
    p_add.add_argument("--password", help="password (default: prompt getpass)")

    p_del = sub.add_parser("delete", help="cancella un utente")
    p_del.add_argument("user")

    p_pw = sub.add_parser("passwd", help="reimposta la password di un utente")
    p_pw.add_argument("user")
    p_pw.add_argument("--password", help="nuova password (default: prompt getpass)")

    return parser


def _ask_password() -> str:
    """Chiede la password due volte (conferma), senza eco a terminale."""
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Conferma password: ")
    if first != second:
        print("Le due password non coincidono.", file=sys.stderr)
        raise SystemExit(1)
    if len(first) < 8:
        print("La password deve avere almeno 8 caratteri.", file=sys.stderr)
        raise SystemExit(1)
    return first


async def _run(args: argparse.Namespace) -> None:
    db = args.db
    if args.command == "list":
        users = await auth.list_users(db)
        if not users:
            print("Nessun utente.")
            return
        for u in users:
            print(f"{u['username']}\t{u['role']}\t{u['created_at']}")
    elif args.command == "add":
        password = args.password or _ask_password()
        try:
            await auth.create_user(db, args.user, password, args.role)
        except ValueError as exc:
            print(f"Errore: {exc}", file=sys.stderr)
            raise SystemExit(1) from None
        print(f"Utente '{args.user}' creato (role={args.role}).")
    elif args.command == "delete":
        removed = await auth.delete_user(db, args.user)
        if not removed:
            print(f"Utente '{args.user}' inesistente.", file=sys.stderr)
            raise SystemExit(1)
        print(f"Utente '{args.user}' cancellato.")
    elif args.command == "passwd":
        password = args.password or _ask_password()
        updated = await auth.set_password(db, args.user, password)
        if not updated:
            print(f"Utente '{args.user}' inesistente.", file=sys.stderr)
            raise SystemExit(1)
        print(f"Password di '{args.user}' aggiornata.")


def main() -> None:
    """Entry point della CLI."""
    parser = _build_parser()
    args = parser.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
