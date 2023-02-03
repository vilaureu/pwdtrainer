#!/usr/bin/python3
"""
Password trainer which stores hashed passwords and compares them on training
sessions.
"""

import argparse
import os
import sqlite3
import unicodedata
from base64 import b64encode
from dataclasses import dataclass
from getpass import getpass
from hashlib import scrypt
from secrets import SystemRandom, compare_digest
from sys import stderr
from typing import Iterator, Optional

from appdirs import user_config_dir

APP_NAME = "pwdtrainer"
APP_AUTHOR = False
CONFIG_DIR = user_config_dir(APP_NAME, APP_AUTHOR)
DATABASE_NAME = "pwdtrainer.sqlite"
SALT_SIZE = 32
SCRYPT_N = 1 << 18
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MEM = 1 << 30
HASH_LEN = 32


def normalize(string: str) -> str:
    """Perform unicode normalization."""
    return unicodedata.normalize("NFC", string)


@dataclass
class Entry:
    """Database password entry."""

    name: str
    hashed: bytes
    salt: bytes
    cost_factor: int
    block_size: int
    parallelism: int

    def __post_init__(self):
        self.name = normalize(self.name)


class Database:
    """Wrapper around the sqlite database interface."""

    def __init__(self):
        os.makedirs(CONFIG_DIR, exist_ok=True)
        path = os.path.join(CONFIG_DIR, DATABASE_NAME)
        self.con = sqlite3.connect(path)
        self.cur = self.con.cursor()

        self.cur.execute(
            (
                "CREATE TABLE IF NOT EXISTS passwords ("
                "   id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, "
                "   name TEXT NOT NULL UNIQUE, "
                "   hash BLOB NOT NULL, "
                "   salt BLOB NOT NULL, "
                "   costFactor INTEGER NOT NULL, "
                "   blockSize INTEGER NOT NULL, "
                "   parallelism INTEGER NOT NULL"
                ")"
            )
        )

    def insert(self, entry: Entry):
        """Insert entry into database."""

        params = (
            entry.name,
            entry.hashed,
            entry.salt,
            entry.cost_factor,
            entry.block_size,
            entry.parallelism,
        )
        self.cur.execute(
            (
                "INSERT INTO passwords "
                "(name, hash, salt, costFactor, blockSize, parallelism) "
                "VALUES (?, ?, ?, ?, ?, ?)"
            ),
            params,
        )
        self.con.commit()

    def delete(self, name: str):
        """Delete entry from database by name."""

        name = normalize(name)
        self.cur.execute("DELETE FROM passwords WHERE name = ?", (name,))
        self.con.commit()

    def entries(self) -> Iterator[Entry]:
        """Return all database entries."""

        rows = self.cur.execute(
            (
                "SELECT name, hash, salt, costFactor, blockSize, parallelism "
                "FROM passwords"
            )
        )
        for row in rows:
            yield Entry(row[0], row[1], row[2], row[3], row[4], row[5])

    def entry(self, name: str) -> Optional[Entry]:
        """Return the specified entry."""

        rows = self.cur.execute(
            (
                "SELECT name, hash, salt, costFactor, blockSize, parallelism "
                "FROM passwords WHERE name = ?"
            ),
            (normalize(name),),
        )
        row = next(rows)
        return Entry(row[0], row[1], row[2], row[3], row[4], row[5])


# pylint: disable=too-many-arguments
def input_hash(
    salt: bytes,
    scrypt_n: int = SCRYPT_N,
    scrypt_r: int = SCRYPT_R,
    scrypt_p: int = SCRYPT_P,
    dklen: int = HASH_LEN,
    prompt: str = "Password: ",
) -> bytes:
    """Request password from stdin and compute hash."""

    password = bytes(normalize(getpass(prompt)), encoding="UTF-8")
    return scrypt(
        password,
        salt=salt,
        n=scrypt_n,
        r=scrypt_r,
        p=scrypt_p,
        maxmem=SCRYPT_MEM,
        dklen=dklen,
    )


def create(args):
    """Create new password entries."""

    salt = os.urandom(SALT_SIZE)
    hashed = input_hash(salt)

    entry = Entry(args.name, hashed, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    try:
        Database().insert(entry)
    except sqlite3.IntegrityError:
        print(f"entry with name '{entry.name}' already exists", file=stderr)


def delete(args):
    """Delete the specified entries."""

    database = Database()
    for name in args.name:
        database.delete(name)


def list_cmd(args):
    """List all password entries."""

    if args.verbose:
        header = "name hash salt cost_factor block_size parallelism"
        print(header)
        print(len(header) * "-")

    for entry in Database().entries():
        hashed = b64encode(entry.hashed).decode("ASCII")
        salt = b64encode(entry.salt).decode("ASCII")

        print(entry.name, end="")
        if args.verbose:
            print(
                "",
                hashed,
                salt,
                entry.cost_factor,
                entry.block_size,
                entry.parallelism,
                end="",
            )
        print()


def train(args):
    """Train passwords in random order."""

    database = Database()
    if args.name:
        entries = []
        for name in args.name:
            try:
                entries.append(database.entry(name))
            except StopIteration:
                print(f"no entry for '{name}' found", file=stderr)
    else:
        entries = list(database.entries())

    random = SystemRandom()
    random.shuffle(entries)
    i = 0
    while True:
        if i >= len(entries):
            break

        entry: Entry = entries[i]
        try:
            hashed = input_hash(
                entry.salt,
                entry.cost_factor,
                entry.block_size,
                entry.parallelism,
                len(entry.hashed),
                f"Password for {entry.name}: ",
            )
        except KeyboardInterrupt:
            print()
            i += 1
            continue

        if compare_digest(hashed, entry.hashed):
            i += 1
        else:
            print(":( incorrect", file=stderr)


def main():
    """Main function parsing command line arguments."""

    parser = argparse.ArgumentParser(
        description=(
            "Password trainer which stores hashed passwords and compares "
            "them on training sessions."
        ),
        epilog=(
            "Copyright (C) 2021, 2023 Viktor Reusch -- "
            "This program comes with ABSOLUTELY NO WARRANTY. "
            "This is free software, and you are welcome to redistribute it "
            "under the conditions of the GNU General Public License version 3 "
            "or later."
        ),
    )
    subparsers = parser.add_subparsers(required=True)

    create_parser = subparsers.add_parser("create", help="create new password entry")
    create_parser.add_argument("name", help="name of the new entry")
    create_parser.set_defaults(func=create)

    delete_parser = subparsers.add_parser("delete", help="delete password entries")
    delete_parser.add_argument("name", nargs="+", help="name of an entry")
    delete_parser.set_defaults(func=delete)

    list_parser = subparsers.add_parser("list", help="list stored password entries")
    list_parser.add_argument(
        "-v", "--verbose", action="store_true", help="print all password properties"
    )
    list_parser.set_defaults(func=list_cmd)

    train_parser = subparsers.add_parser("train", help="ask for and check passwords")
    train_parser.add_argument("name", nargs="*", help="name of the password to train")
    train_parser.set_defaults(func=train)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
