#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Piano Vault - DB-based filename restorer

What it does:
1) Opens a recovered backup ZIP (or a folder containing the extracted backup).
2) Automatically finds the SQLite database, even if the DB file has no extension.
3) Reads tbl_file_info and builds:
       encryptName -> originalName
4) Renames decrypted .recovered files using their original filenames.

Examples:
    python rename_from_db.py ".\backup.recovered" --recovered ".\recovered"
    python rename_from_db.py ".\backup.zip" --recovered ".\recovered"
    python rename_from_db.py ".\backup_extracted" --recovered ".\recovered"
"""

import argparse
import shutil
import sqlite3
import tempfile
import zipfile
from pathlib import Path


SQLITE_MAGIC = b"SQLite format 3\x00"


def is_sqlite(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def prepare_backup(source: Path, temp_root: Path) -> Path:
    """Return a directory containing the backup files."""
    if source.is_dir():
        return source

    if zipfile.is_zipfile(source):
        extract_dir = temp_root / "backup"
        extract_dir.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(source, "r") as zf:
            zf.extractall(extract_dir)
        return extract_dir

    raise RuntimeError(
        f"Backup is neither a directory nor a valid ZIP file: {source}\n"
        "Make sure you pass the recovered backup file (the one that opens as ZIP)."
    )


def find_databases(root: Path):
    dbs = []
    for p in root.rglob("*"):
        if p.is_file() and is_sqlite(p):
            dbs.append(p)
    return dbs


def get_tables(db_path: Path):
    with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as conn:
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        return [row[0] for row in cur.fetchall()]


def quote_ident(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def read_filename_map(db_path: Path):
    """
    Reads all SQLite tables and looks for columns equivalent to:
    encryptName / encrypted name
    originalName / original name

    Returns dict: encrypted filename -> original filename
    """
    result = {}
    tables = get_tables(db_path)

    preferred_tables = ["tbl_file_info"] + [t for t in tables if t != "tbl_file_info"]

    with sqlite3.connect(f"file:{db_path.as_posix()}?mode=ro", uri=True) as conn:
        for table in preferred_tables:
            try:
                cur = conn.execute(f"PRAGMA table_info({quote_ident(table)})")
                cols = [row[1] for row in cur.fetchall()]
            except sqlite3.DatabaseError:
                continue

            lower = {c.lower(): c for c in cols}

            encrypted_col = None
            original_col = None

            for candidate in (
                "encryptname", "encryptedname", "encrypt_name",
                "encrypted_name", "lockedname", "locked_name"
            ):
                if candidate in lower:
                    encrypted_col = lower[candidate]
                    break

            for candidate in (
                "originalname", "original_name", "filename",
                "file_name", "name"
            ):
                if candidate in lower:
                    original_col = lower[candidate]
                    break

            if not encrypted_col or not original_col:
                continue

            query = (
                f"SELECT {quote_ident(encrypted_col)}, "
                f"{quote_ident(original_col)} "
                f"FROM {quote_ident(table)}"
            )

            try:
                rows = conn.execute(query).fetchall()
            except sqlite3.DatabaseError:
                continue

            for encrypted_name, original_name in rows:
                if encrypted_name and original_name:
                    result[str(encrypted_name)] = Path(str(original_name)).name

    return result


def recovered_candidates(recovered_dir: Path, encrypted_name: str):
    """
    Tries common output names produced by the recovery script.
    """
    enc = Path(encrypted_name).name
    stem = Path(enc).stem

    candidates = [
        recovered_dir / (enc + ".recovered"),
        recovered_dir / (stem + ".recovered"),
        recovered_dir / enc.replace(".locked", ".recovered"),
        recovered_dir / (stem + ".recovered"),
    ]

    # Remove duplicates while preserving order.
    seen = set()
    out = []
    for p in candidates:
        key = str(p).lower()
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def unique_destination(dest: Path) -> Path:
    if not dest.exists():
        return dest

    stem = dest.stem
    suffix = dest.suffix
    n = 2
    while True:
        candidate = dest.with_name(f"{stem} ({n}){suffix}")
        if not candidate.exists():
            return candidate
        n += 1


def main():
    parser = argparse.ArgumentParser(
        description="Restore original filenames of recovered Piano Vault files from backup SQLite DB."
    )
    parser.add_argument(
        "backup",
        help="Recovered backup ZIP file or extracted backup folder"
    )
    parser.add_argument(
        "--recovered",
        required=True,
        help="Folder containing decrypted .recovered files"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be renamed without changing files"
    )
    parser.add_argument(
        "--copy",
        action="store_true",
        help="Copy files instead of renaming/moving them"
    )
    args = parser.parse_args()

    backup = Path(args.backup).resolve()
    recovered_dir = Path(args.recovered).resolve()

    if not backup.exists():
        raise SystemExit(f"Backup not found: {backup}")
    if not recovered_dir.is_dir():
        raise SystemExit(f"Recovered folder not found: {recovered_dir}")

    print("Piano Vault Filename Restorer")
    print("=" * 32)
    print(f"Backup:    {backup}")
    print(f"Recovered: {recovered_dir}")
    print()

    with tempfile.TemporaryDirectory(prefix="piano_backup_") as tmp:
        backup_root = prepare_backup(backup, Path(tmp))

        dbs = find_databases(backup_root)
        if not dbs:
            raise SystemExit(
                "No SQLite database found inside the backup.\n"
                "The DB file may not be the recovered/complete backup."
            )

        print("[+] SQLite database(s) found:")
        for db in dbs:
            print(f"    {db.relative_to(backup_root)}")
        print()

        mapping = {}
        for db in dbs:
            try:
                current = read_filename_map(db)
                if current:
                    print(f"[+] {db.name}: {len(current)} filename mapping(s)")
                    mapping.update(current)
            except Exception as e:
                print(f"[!] Could not read {db}: {e}")

        if not mapping:
            raise SystemExit(
                "No encryptName -> originalName mappings were found.\n"
                "The database schema may differ; the script needs to be adjusted for that DB."
            )

        print()
        print(f"[+] Total mappings: {len(mapping)}")
        print()

        renamed = 0
        missing = 0

        for encrypted_name, original_name in mapping.items():
            source = next((p for p in recovered_candidates(recovered_dir, encrypted_name) if p.exists()), None)

            if source is None:
                print(f"[?] Missing recovered file for: {encrypted_name}")
                missing += 1
                continue

            dest = unique_destination(recovered_dir / original_name)

            if args.dry_run:
                print(f"[DRY] {source.name}  ->  {dest.name}")
                renamed += 1
                continue

            if args.copy:
                shutil.copy2(source, dest)
                print(f"[COPY] {source.name}  ->  {dest.name}")
            else:
                source.rename(dest)
                print(f"[OK]   {source.name}  ->  {dest.name}")
            renamed += 1

        print()
        print("=" * 32)
        print(f"Done.")
        print(f"Mapped/renamed: {renamed}")
        print(f"Missing:        {missing}")

        if missing:
            print()
            print("Note: Missing entries usually mean either:")
            print("  - the corresponding .locked file was not decrypted yet, or")
            print("  - your recovery script uses a different output filename format.")


if __name__ == "__main__":
    main()
