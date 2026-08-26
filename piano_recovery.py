#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Piano Vault Recovery Tool
=========================

Decrypts files encrypted by the Piano Vault Android application,
extracts the vault password, reads backup metadata, restores
original filenames, and embeds metadata (dates, EXIF) into recovered files.

Usage:
    python piano_recovery.py <locked_folder> --out <output_folder>
    python piano_recovery.py .\\locked --out .\\recovered
    python piano_recovery.py .\\locked --out .\\recovered --dry-run
    python piano_recovery.py .\\locked --out .\\recovered --decrypt-only
    python piano_recovery.py .\\locked --out .\\recovered --skip-decrypt

Requirements:
    pip install cryptography piexif
"""

import argparse
import json
import os
import re
import sqlite3
import struct
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("ERROR: Missing 'cryptography'. Install: pip install cryptography")
    sys.exit(2)

try:
    import piexif
    HAS_PIEXIF = True
except ImportError:
    HAS_PIEXIF = False


# ============================================================
# Crypto parameters (extracted from libPiano.so via Ghidra)
# ============================================================

STREAM_KEY = bytes.fromhex("29d3b7ff1be51f73b1ca82b53081b820")
PASSWORD_KEY = bytes.fromhex("763022eeb50a28b41599d61a1affcedb")
AAD = b"@Secret(|)Piano@"

SEGMENT_SIZE = 1048576
DERIVED_KEY_SIZE = 16
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 7
HEADER_SIZE = 1 + DERIVED_KEY_SIZE + NONCE_PREFIX_SIZE  # 24
FIRST_SEGMENT_OFFSET = 0

WEBP_HEADER_SIZE = 246
PASSWORD_BLOCK_SIZE = 200
FULL_APP_HEADER_SIZE = 446

TINK_AEAD_PREFIX_SIZE = 5
TINK_AEAD_IV_SIZE = 12
TINK_AEAD_TAG_SIZE = 16


# ============================================================
# Helpers
# ============================================================

def safe_print(text):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("ascii", errors="replace").decode("ascii"))


def ts_to_str(ts_ms):
    if not ts_ms or ts_ms == 0:
        return "-"
    try:
        dt = datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OSError, ValueError):
        return str(ts_ms)


def ts_to_datetime(ts_ms):
    if not ts_ms or ts_ms == 0:
        return None
    try:
        return datetime.fromtimestamp(ts_ms / 1000.0, tz=timezone.utc)
    except (OSError, ValueError):
        return None


def extract_date_from_filename(filename: str):
    """
    Extract date from WhatsApp-style filenames.
    Patterns: IMG-20260818-WA0056.jpg, VID-20260825-WA0022.mp4
    """
    match = re.search(r'(\d{4})(\d{2})(\d{2})', filename)
    if match:
        try:
            year, month, day = int(match.group(1)), int(match.group(2)), int(match.group(3))
            if 2000 <= year <= 2100 and 1 <= month <= 12 and 1 <= day <= 31:
                return datetime(year, month, day, 12, 0, 0, tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


# ============================================================
# File type detection
# ============================================================

def detect_file_type(path: Path):
    try:
        with open(path, "rb") as f:
            data = f.read(4096)
    except Exception as e:
        return None, f"Read error: {e}"

    if data.startswith(b"\xFF\xD8\xFF"):
        return ".jpg", "JPEG image"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png", "PNG image"
    if data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        return ".gif", "GIF image"
    if data.startswith(b"BM"):
        return ".bmp", "BMP image"
    if data.startswith(b"RIFF") and len(data) >= 12:
        if data[8:12] == b"WEBP":
            return ".webp", "WebP image"
        if data[8:12] == b"WAVE":
            return ".wav", "WAV audio"
        if data[8:12] == b"AVI ":
            return ".avi", "AVI video"
    if len(data) >= 12 and data[4:8] == b"ftyp":
        return ".mp4", "MP4 video"
    if data.startswith(b"\x1A\x45\xDF\xA3"):
        return ".webm" if b"webm" in data.lower() else ".mkv", "Video"
    if data.startswith(b"ID3") or (len(data) >= 2 and data[:2] in (b"\xFF\xFB", b"\xFF\xF3", b"\xFF\xF2")):
        return ".mp3", "MP3 audio"
    if data.startswith(b"OggS"):
        return ".ogg", "Ogg media"
    if data.startswith(b"fLaC"):
        return ".flac", "FLAC audio"
    if data.startswith(b"%PDF-"):
        return ".pdf", "PDF document"
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        try:
            with zipfile.ZipFile(path, "r") as z:
                names = z.namelist()
                if any(n.startswith("word/") for n in names):
                    return ".docx", "Word document"
                if any(n.startswith("xl/") for n in names):
                    return ".xlsx", "Excel spreadsheet"
                if any(n.startswith("ppt/") for n in names):
                    return ".pptx", "PowerPoint presentation"
        except Exception:
            pass
        return ".zip", "ZIP archive"
    if data.startswith(b"\x1F\x8B\x08"):
        return ".gz", "GZIP archive"
    if data.startswith(b"Rar!\x1A\x07"):
        return ".rar", "RAR archive"
    if data.startswith(b"SQLite format 3\x00"):
        return ".db", "SQLite database"
    return None, "Unknown"


# ============================================================
# EXIF metadata injection
# ============================================================

def set_jpeg_exif(filepath: Path, date_taken: datetime = None,
                  original_path: str = None, comment: str = None):
    """
    Add EXIF metadata to a JPEG file.
    - DateTimeOriginal / DateTimeDigitized from date_taken
    - ImageDescription from comment
    - UserComment with original path info
    """
    if not HAS_PIEXIF:
        return False

    try:
        # Try to load existing EXIF
        try:
            exif_dict = piexif.load(str(filepath))
        except Exception:
            exif_dict = {"0th": {}, "Exif": {}, "GPS": {}, "1st": {}, "Interop": {}}

        modified = False

        if date_taken:
            date_str = date_taken.strftime("%Y:%m:%d %H:%M:%S")
            date_bytes = date_str.encode("ascii")

            # Set DateTimeOriginal (when photo was taken)
            if piexif.ExifIFD.DateTimeOriginal not in exif_dict["Exif"] or \
               not exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal]:
                exif_dict["Exif"][piexif.ExifIFD.DateTimeOriginal] = date_bytes
                modified = True

            # Set DateTimeDigitized
            if piexif.ExifIFD.DateTimeDigitized not in exif_dict["Exif"] or \
               not exif_dict["Exif"][piexif.ExifIFD.DateTimeDigitized]:
                exif_dict["Exif"][piexif.ExifIFD.DateTimeDigitized] = date_bytes
                modified = True

            # Set DateTime (file modification in EXIF)
            if piexif.ImageIFD.DateTime not in exif_dict["0th"] or \
               not exif_dict["0th"][piexif.ImageIFD.DateTime]:
                exif_dict["0th"][piexif.ImageIFD.DateTime] = date_bytes
                modified = True

        if comment:
            exif_dict["0th"][piexif.ImageIFD.ImageDescription] = comment.encode("utf-8")
            modified = True

        if original_path:
            # Store original path as UserComment
            user_comment = f"Original: {original_path}".encode("utf-8")
            # piexif UserComment needs ASCII prefix
            ascii_prefix = b"ASCII\x00\x00\x00"
            exif_dict["Exif"][piexif.ExifIFD.UserComment] = ascii_prefix + user_comment
            modified = True

        # Add software tag
        exif_dict["0th"][piexif.ImageIFD.Software] = b"Piano Vault Recovery Tool"

        if modified:
            exif_bytes = piexif.dump(exif_dict)
            piexif.insert(exif_bytes, str(filepath))
            return True

    except Exception as e:
        safe_print(f"        [!] EXIF write warning: {e}")

    return False


def set_file_timestamps(filepath: Path, dt: datetime):
    """Set file modification and access time."""
    try:
        ts = dt.timestamp()
        os.utime(str(filepath), (ts, ts))
        return True
    except Exception:
        return False


# ============================================================
# Tink AEAD password decryption
# ============================================================

def decrypt_password_block(data: bytes, offset: int = WEBP_HEADER_SIZE):
    block = data[offset: offset + PASSWORD_BLOCK_SIZE]
    if len(block) < PASSWORD_BLOCK_SIZE:
        return None

    terminator_pos = None
    for i in range(len(block)):
        if block[i] == 0x0A and all(b == 0 for b in block[i + 1:]):
            terminator_pos = i
            break

    ct = block[:terminator_pos] if terminator_pos is not None else block.rstrip(b"\x00")
    min_len = TINK_AEAD_PREFIX_SIZE + TINK_AEAD_IV_SIZE + TINK_AEAD_TAG_SIZE
    if len(ct) < min_len:
        return None

    raw = ct[TINK_AEAD_PREFIX_SIZE:]
    if len(raw) < TINK_AEAD_IV_SIZE + TINK_AEAD_TAG_SIZE:
        return None

    iv = raw[:TINK_AEAD_IV_SIZE]
    ct_and_tag = raw[TINK_AEAD_IV_SIZE:]

    for aad in (AAD, None):
        try:
            return AESGCM(PASSWORD_KEY).decrypt(iv, ct_and_tag, aad).decode("utf-8")
        except Exception:
            continue
    return None


# ============================================================
# Streaming decryption
# ============================================================

def looks_like_webp(data: bytes) -> bool:
    return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"


def locate_streaming_offset(data: bytes) -> int:
    for offset in (FULL_APP_HEADER_SIZE, WEBP_HEADER_SIZE):
        if len(data) >= offset + HEADER_SIZE and data[offset] == HEADER_SIZE:
            return offset
    raise ValueError("Cannot find Tink StreamingAead header.")


def parse_stream_header(sd: bytes):
    if len(sd) < HEADER_SIZE or sd[0] != HEADER_SIZE:
        raise ValueError("Bad Tink header.")
    return sd[1: 1 + DERIVED_KEY_SIZE], sd[1 + DERIVED_KEY_SIZE: HEADER_SIZE]


def derive_stream_key(salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=DERIVED_KEY_SIZE,
                salt=salt, info=AAD).derive(STREAM_KEY)


def make_nonce(pfx: bytes, seg: int, last: bool) -> bytes:
    return pfx + struct.pack(">I", seg) + bytes([1 if last else 0])


def decrypt_stream(sd: bytes) -> bytes:
    salt, npfx = parse_stream_header(sd)
    aes = AESGCM(derive_stream_key(salt))
    ct = sd[HEADER_SIZE:]
    if len(ct) < TAG_SIZE:
        raise ValueError("Ciphertext too short.")

    pt = bytearray()
    first_seg = SEGMENT_SIZE - HEADER_SIZE - FIRST_SEGMENT_OFFSET
    pos, sn = 0, 0

    while pos < len(ct):
        sl = min(first_seg if sn == 0 else SEGMENT_SIZE, len(ct) - pos)
        seg = ct[pos: pos + sl]
        last = (pos + sl == len(ct))
        if len(seg) < TAG_SIZE:
            raise ValueError(f"Segment {sn} too short.")
        pt.extend(aes.decrypt(make_nonce(npfx, sn, last), seg, None))
        pos += sl
        sn += 1

    return bytes(pt)


def recover_file(input_path: Path, output_dir: Path):
    data = input_path.read_bytes()
    if not looks_like_webp(data):
        raise ValueError("Not a Piano Vault file.")

    so = locate_streaming_offset(data)
    pwd = decrypt_password_block(data, WEBP_HEADER_SIZE) if so == FULL_APP_HEADER_SIZE else None
    pt = decrypt_stream(data[so:])

    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"{input_path.stem}.recovered"
    out.write_bytes(pt)
    return so, out, len(pt), pwd


# ============================================================
# File type renaming
# ============================================================

def get_unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    n = 1
    while True:
        c = path.with_name(f"{path.stem} ({n}){path.suffix}")
        if not c.exists():
            return c
        n += 1


def rename_recovered_files(output_dir: Path) -> dict:
    recovered = sorted(output_dir.rglob("*.recovered"))
    counts = {}
    if not recovered:
        safe_print("    No .recovered files to rename.")
        return counts

    for fp in recovered:
        ext, desc = detect_file_type(fp)
        if ext is None:
            safe_print(f"    [?] {fp.name} -- Unknown")
            counts["Unknown"] = counts.get("Unknown", 0) + 1
            continue
        new = get_unique_path(fp.with_suffix(ext))
        try:
            fp.rename(new)
            label = desc.split("/")[0].strip()
            counts[label] = counts.get(label, 0) + 1
            safe_print(f"    [OK] {fp.name} -> {new.name}  ({desc})")
        except Exception as e:
            safe_print(f"    [!] Rename failed: {e}")
    return counts


# ============================================================
# Backup DB reading
# ============================================================

SQLITE_MAGIC = b"SQLite format 3\x00"

def is_sqlite(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            return f.read(16) == SQLITE_MAGIC
    except OSError:
        return False


def read_backup(backup_path: Path):
    config, file_rows, folder_map = {}, [], {}

    with tempfile.TemporaryDirectory(prefix="piano_") as tmp:
        tp = Path(tmp)
        if zipfile.is_zipfile(backup_path):
            with zipfile.ZipFile(backup_path, "r") as zf:
                zf.extractall(tp)
        elif backup_path.is_dir():
            tp = backup_path
        else:
            return config, file_rows, folder_map

        cf = tp / "config"
        if cf.exists():
            try:
                config = json.loads(cf.read_text(encoding="utf-8"))
            except Exception:
                pass

        for dbp in tp.rglob("*"):
            if dbp.is_file() and is_sqlite(dbp):
                conn = sqlite3.connect(f"file:{dbp.as_posix()}?mode=ro", uri=True)
                conn.row_factory = sqlite3.Row
                try:
                    for r in conn.execute("SELECT * FROM tbl_folder_info"):
                        folder_map[r["id"]] = dict(r)
                except Exception:
                    pass
                try:
                    for r in conn.execute("SELECT * FROM tbl_file_info"):
                        file_rows.append(dict(r))
                except Exception:
                    pass
                conn.close()

    return config, file_rows, folder_map


def find_recovered_file(d: Path, enc_name: str) -> Path:
    enc = Path(enc_name).name
    base = enc[:-len(".locked")] if enc.endswith(".locked") else enc
    for c in d.iterdir():
        if not c.is_file():
            continue
        cn = c.name
        if cn.startswith(base):
            rest = cn[len(base):]
            if rest == "" or rest.startswith("."):
                return c
    return None


# ============================================================
# Report generation
# ============================================================

FILE_TYPE_NAMES = {0: "Image", 1: "Video", 2: "Other"}


def generate_report(output_dir: Path, config: dict, file_rows: list,
                    folder_map: dict, passwords: set):
    """Write recovery_report.txt with all DB metadata."""
    report_path = output_dir / "recovery_report.txt"
    lines = []
    def w(t=""):
        lines.append(t)

    w("=" * 65)
    w("  PIANO VAULT - RECOVERY REPORT")
    w("=" * 65)
    w(f"  Generated: {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    w(f"  Output:    {output_dir}")
    w()

    if passwords:
        w("-" * 65)
        w("  VAULT PASSWORD(S)")
        w("-" * 65)
        for p in passwords:
            w(f"  >>> {p}")
        w()

    if config:
        w("-" * 65)
        w("  BACKUP CONFIG (from backup.zip/config)")
        w("-" * 65)
        for k, v in config.items():
            w(f"  {k}: {v}")
        w()

    if folder_map:
        w("-" * 65)
        w("  VAULT FOLDERS")
        w("-" * 65)
        w(f"  {'ID':<5} {'Name':<25} {'Type':<10} {'Encrypted Name':<40} {'Created'}")
        w(f"  {'--':<5} {'----':<25} {'----':<10} {'-' * 14:<40} {'-------'}")
        for fid, info in sorted(folder_map.items()):
            ft = FILE_TYPE_NAMES.get(info.get("folderType", -1), "?")
            w(f"  {fid:<5} {info.get('origFolderName','?'):<25} {ft:<10} "
              f"{info.get('encryptFolderName','?'):<40} {ts_to_str(info.get('createDate'))}")
        w()

    if file_rows:
        w("-" * 65)
        w(f"  FILE DATABASE ({len(file_rows)} files)")
        w("-" * 65)
        for row in file_rows:
            fld = folder_map.get(row.get("folderId", -1), {})
            folder_name = fld.get("origFolderName", "?")
            ft = FILE_TYPE_NAMES.get(row.get("fileType", -1), "?")
            recycled = "YES" if row.get("isFromRecycle") else "No"
            fname_date = extract_date_from_filename(row.get("originalName", ""))

            w()
            w(f"  --- File ID: {row.get('id', '?')} ---")
            w(f"  Original Name:     {row.get('originalName', '?')}")
            w(f"  Encrypted Name:    {row.get('encryptName', '?')}")
            w(f"  Vault Folder:      {folder_name} (ID={row.get('folderId', '?')})")
            w(f"  File Type:         {ft}")
            w(f"  File Size:         {row.get('fileSize', 0):,} bytes")
            w(f"  Original Path:     {row.get('originalPath', '?')}")
            w(f"  Encrypted Path:    {row.get('filePath', '?')}")
            w(f"  Added to Vault:    {ts_to_str(row.get('createDate'))}")
            w(f"  In Recycle Bin:    {recycled}")
            if row.get("recycleTime") and row["recycleTime"] != 0:
                w(f"  Recycle Time:      {ts_to_str(row['recycleTime'])}")
            if fname_date:
                w(f"  Date (filename):   {fname_date.strftime('%Y-%m-%d')}")
            w(f"  Cloud Sync:        {'Enabled' if row.get('isSyncEnabled') else 'Disabled'}")
            if row.get("driveId"):
                w(f"  Drive ID:          {row['driveId']}")
        w()

    w("-" * 65)
    w("  RECOVERED FILES")
    w("-" * 65)
    for fp in sorted(output_dir.rglob("*")):
        if fp.is_file() and fp.name != "recovery_report.txt":
            rel = fp.relative_to(output_dir)
            mtime = datetime.fromtimestamp(fp.stat().st_mtime, tz=timezone.utc)
            w(f"  {str(rel):<55} {fp.stat().st_size:>10,} bytes  {mtime.strftime('%Y-%m-%d')}")
    w()
    w("=" * 65)
    w("  END OF REPORT")
    w("=" * 65)

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


# ============================================================
# Main pipeline
# ============================================================


def main():
    parser = argparse.ArgumentParser(description="Piano Vault Recovery Tool")
    parser.add_argument("input", help="Folder with .locked files")
    parser.add_argument("--out", default="recovered", help="Output directory")
    parser.add_argument("--dry-run", action="store_true", help="Preview without changes")
    parser.add_argument("--decrypt-only", action="store_true", help="Only decrypt")
    parser.add_argument("--skip-decrypt", action="store_true", help="Skip decryption")
    parser.add_argument("--no-exif", action="store_true", help="Skip EXIF metadata injection")
    args = parser.parse_args()

    input_dir = Path(args.input).resolve()
    output_dir = Path(args.out).resolve()

    if not input_dir.is_dir():
        safe_print(f"ERROR: Not a directory: {input_dir}")
        return 1

    safe_print("")
    safe_print("=" * 55)
    safe_print("    Piano Vault Recovery Tool")
    safe_print("=" * 55)
    safe_print(f"  Input:  {input_dir}")
    safe_print(f"  Output: {output_dir}")
    if HAS_PIEXIF and not args.no_exif:
        safe_print("  EXIF:   Enabled (piexif)")
    else:
        safe_print("  EXIF:   Disabled" + (" (--no-exif)" if args.no_exif else " (pip install piexif)"))
    safe_print("")

    # ---- Stage 1: Discover ----
    locked = sorted(input_dir.rglob("*.locked"))
    safe_print(f"[1/6] Discovering encrypted files...")
    safe_print(f"      Found: {len(locked)}")
    safe_print("")

    if not locked:
        safe_print("No .locked files found.")
        return 0

    # ---- Stage 2: Decrypt ----
    passwords = set()
    success, failed = 0, 0

    if not args.skip_decrypt:
        safe_print(f"[2/6] Decrypting files...")
        safe_print(f"      {'-' * 50}")
        output_dir.mkdir(parents=True, exist_ok=True)

        for i, p in enumerate(locked, 1):
            safe_print(f"  [{i}/{len(locked)}] {p.name}")
            try:
                off, out, sz, pwd = recover_file(p, output_dir)
                line = f"      OK | offset={off} | {sz:,} bytes"
                if pwd:
                    line += f" | PASSWORD: {pwd}"
                    passwords.add(pwd)
                safe_print(line)
                safe_print(f"      -> {out.name}")
                success += 1
            except Exception as exc:
                safe_print(f"      FAILED: {exc}")
                failed += 1

        safe_print("")
        safe_print(f"      Decrypted: {success} OK / {failed} Failed")
        safe_print("")
    else:
        safe_print("[2/6] Skipping decryption (--skip-decrypt)")
        safe_print("")

    # ---- Stage 3: Detect types ----
    safe_print("[3/6] Detecting file types...")
    type_counts = rename_recovered_files(output_dir)
    if type_counts:
        safe_print(f"      Breakdown: {type_counts}")
    safe_print("")

    # ---- Stage 4: Read backup ----
    safe_print("[4/6] Reading backup config & database...")

    backup_path = None
    for name in ("backup.zip", "backup.recovered"):
        c = output_dir / name
        if c.exists():
            backup_path = c
            break

    config, file_rows, folder_map = {}, [], {}

    if backup_path:
        safe_print(f"      Backup: {backup_path.name}")
        config, file_rows, folder_map = read_backup(backup_path)

        if config:
            safe_print("")
            safe_print("      --- Backup Config ---")
            for k, v in config.items():
                safe_print(f"      {k}: {v}")
            if "password" in config:
                passwords.add(str(config["password"]))

        if folder_map:
            safe_print("")
            safe_print("      --- Vault Folders ---")
            safe_print(f"      {'ID':<4} {'Name':<20} {'Type':<8} {'Created'}")
            for fid, info in sorted(folder_map.items()):
                ft = FILE_TYPE_NAMES.get(info.get("folderType", -1), "?")
                safe_print(f"      {fid:<4} {info.get('origFolderName','?'):<20} {ft:<8} {ts_to_str(info.get('createDate'))}")

        if file_rows:
            safe_print("")
            safe_print("      --- File Database ---")
            safe_print(f"      {len(file_rows)} file(s):")
            safe_print("")
            for row in file_rows:
                fld = folder_map.get(row.get("folderId", -1), {})
                fn = fld.get("origFolderName", "?")
                ft = FILE_TYPE_NAMES.get(row.get("fileType", -1), "?")
                rec = "YES" if row.get("isFromRecycle") else "no"
                safe_print(f"      ID={row.get('id','')} | {row.get('originalName','?')}")
                safe_print(f"        Folder: {fn} | Type: {ft} | Size: {row.get('fileSize',0):,} bytes")
                safe_print(f"        Source: {row.get('originalPath','?')}")
                safe_print(f"        Added to vault: {ts_to_str(row.get('createDate'))} | Recycled: {rec}")
                if row.get("recycleTime") and row["recycleTime"] != 0:
                    safe_print(f"        Recycle time: {ts_to_str(row['recycleTime'])}")
                # Extract date from filename
                fname_date = extract_date_from_filename(row.get("originalName", ""))
                if fname_date:
                    safe_print(f"        Date from filename: {fname_date.strftime('%Y-%m-%d')}")
                safe_print("")
    else:
        safe_print("      No backup file found.")

    safe_print("")

    if passwords:
        safe_print("  +------------------------------------------+")
        safe_print("  |  VAULT PASSWORD(S) FOUND:                |")
        safe_print("  +------------------------------------------+")
        for pwd in passwords:
            safe_print(f"  |  >>> {pwd:<36} |")
        safe_print("  +------------------------------------------+")
        safe_print("")

    # ---- Stage 5: Restore filenames ----
    if args.decrypt_only or not file_rows:
        if args.decrypt_only:
            safe_print("[5/6] Skipping filename restoration (--decrypt-only)")
        elif not file_rows:
            safe_print("[5/6] No DB mappings. Skipping.")
        safe_print("")
    else:
        safe_print("[5/6] Restoring original filenames...")
        renamed, missing, skipped = 0, 0, 0

        for row in file_rows:
            enc_name = row.get("encryptName", "")
            orig_name = row.get("originalName", "")
            if not enc_name or not orig_name:
                continue

            source = find_recovered_file(output_dir, enc_name)
            if source is None:
                if row.get("isFromRecycle", 0):
                    safe_print(f"    [SKIP] {orig_name} (recycled, not present)")
                    skipped += 1
                else:
                    safe_print(f"    [?] Missing: {enc_name}")
                    missing += 1
                continue

            fld = folder_map.get(row.get("folderId", -1), {})
            folder_name = fld.get("origFolderName", "")

            if folder_name:
                dest_dir = output_dir / folder_name
                dest_dir.mkdir(parents=True, exist_ok=True)
            else:
                dest_dir = output_dir

            dest = get_unique_path(dest_dir / orig_name)

            if args.dry_run:
                safe_print(f"    [DRY] {source.name} -> {dest.relative_to(output_dir)}")
            else:
                source.rename(dest)
                safe_print(f"    [OK]  {source.name} -> {dest.relative_to(output_dir)}")
            renamed += 1

        safe_print("")
        safe_print(f"      Renamed: {renamed} | Missing: {missing} | Recycled: {skipped}")
        safe_print("")

    # ---- Stage 6: Embed metadata ----
    if args.decrypt_only or args.no_exif or not file_rows or args.dry_run:
        reason = ""
        if args.decrypt_only:
            reason = "--decrypt-only"
        elif args.no_exif:
            reason = "--no-exif"
        elif args.dry_run:
            reason = "--dry-run"
        elif not file_rows:
            reason = "no DB"
        safe_print(f"[6/6] Skipping metadata embedding ({reason})")
        safe_print("")
    else:
        safe_print("[6/6] Embedding metadata into recovered files...")
        exif_ok, ts_ok = 0, 0

        # Build lookup: encrypted name -> DB row
        db_lookup = {}
        for row in file_rows:
            enc = row.get("encryptName", "")
            if enc:
                base = enc[:-len(".locked")] if enc.endswith(".locked") else enc
                db_lookup[base] = row

        # Process all recovered files
        for fp in sorted(output_dir.rglob("*")):
            if not fp.is_file() or fp.suffix == ".zip":
                continue

            # Try to find the DB row for this file
            row = None
            orig_name = fp.name

            # Match by original name
            for r in file_rows:
                if r.get("originalName") == fp.name:
                    row = r
                    break

            if row is None:
                continue

            create_date = ts_to_datetime(row.get("createDate"))
            fname_date = extract_date_from_filename(row.get("originalName", ""))
            original_path = row.get("originalPath", "")
            fld = folder_map.get(row.get("folderId", -1), {})
            folder_name = fld.get("origFolderName", "")

            # Determine best date: filename date > createDate
            best_date = fname_date or create_date

            # Set filesystem timestamps
            if best_date:
                if set_file_timestamps(fp, best_date):
                    ts_ok += 1
                    safe_print(f"    [TS]   {fp.name} -> mtime={best_date.strftime('%Y-%m-%d %H:%M')}")

            # Embed EXIF for JPEG files
            if fp.suffix.lower() in (".jpg", ".jpeg") and HAS_PIEXIF:
                comment = f"Recovered from Piano Vault | Folder: {folder_name}"
                if set_jpeg_exif(fp, date_taken=best_date,
                                 original_path=original_path,
                                 comment=comment):
                    exif_ok += 1
                    date_label = best_date.strftime('%Y-%m-%d') if best_date else "none"
                    safe_print(f"    [EXIF] {fp.name} -> DateTimeOriginal={date_label}")
                    if original_path:
                        safe_print(f"           UserComment=Original: {original_path}")

        safe_print("")
        safe_print(f"      Timestamps set: {ts_ok} | EXIF injected: {exif_ok}")
        safe_print("")

    # ---- Generate report file ----
    if file_rows or passwords or config:
        report_path = generate_report(output_dir, config, file_rows, folder_map, passwords)
        safe_print(f"  Report saved: {report_path.name}")
        safe_print("")

    # ---- Summary ----
    safe_print("=" * 55)
    safe_print("    Recovery Complete!")
    safe_print("=" * 55)
    safe_print(f"  Output: {output_dir}")
    if passwords:
        safe_print(f"  Vault password: {', '.join(passwords)}")

    # List final files
    safe_print("")
    safe_print("  Final recovered files:")
    for fp in sorted(output_dir.rglob("*")):
        if fp.is_file():
            rel = fp.relative_to(output_dir)
            mtime = datetime.fromtimestamp(fp.stat().st_mtime, tz=timezone.utc)
            safe_print(f"    {rel}  ({fp.stat().st_size:,} bytes, {mtime.strftime('%Y-%m-%d')})")

    safe_print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
