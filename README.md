# Piano Vault Recovery Tool

A reverse-engineering and file recovery tool for the **Piano Vault** (Hide Photos & Videos) Android application. This tool decrypts files encrypted by the app, extracts the vault password, recovers original filenames from the backup database, and embeds metadata (EXIF dates, original paths) into recovered files.

> **Disclaimer:** This tool is intended for legitimate data recovery of **your own files**. Use responsibly and in compliance with applicable laws.

## Features

- **Full decryption** of `.locked` files encrypted by Piano Vault using Google Tink (AES-GCM-HKDF streaming encryption)
- **Vault password extraction** from encrypted password blocks embedded in each file and from the backup config
- **Automatic file type detection** (JPEG, PNG, MP4, ZIP, PDF, etc.) via magic bytes
- **Backup database parsing** — reads the SQLite database inside `backup.zip` to recover:
  - Original filenames
  - Original file paths on the device
  - Vault folder structure
  - File creation dates
  - Recycle bin status
- **Original filename restoration** — renames files back to their real names, organized into vault folders (`My Pictures/`, `My Videos/`, etc.)
- **EXIF metadata injection** — writes `DateTimeOriginal`, `DateTimeDigitized`, `UserComment` (with original path), and `ImageDescription` into recovered JPEG files
- **File timestamp restoration** — sets filesystem modification times from database dates or filename-extracted dates
- **Detailed recovery report** — generates `recovery_report.txt` with all database metadata

## How It Works

Piano Vault disguises itself as a piano app. Users enter a PIN via piano keys to unlock a hidden file vault. The app encrypts each file individually using:

1. **246-byte WebP dummy header** — makes encrypted files appear as images
2. **200-byte AEAD password block** (optional) — the vault PIN encrypted with Tink AES-GCM
3. **Tink AesGcmHkdfStreaming ciphertext** — the actual encrypted file content

The encryption keys are hardcoded inside the native library `libPiano.so` and were extracted using Ghidra reverse engineering.

```
Encrypted file layout:
┌──────────────────────────┐
│ WebP header (246 bytes)  │ ← Camouflage
├──────────────────────────┤
│ Password block (200 B)   │ ← Tink AEAD encrypted PIN
├──────────────────────────┤
│ StreamingAead ciphertext │ ← AES-GCM-HKDF encrypted data
└──────────────────────────┘
```

## Requirements

- Python 3.8+
- Dependencies:
  ```
  pip install cryptography piexif
  ```

## Usage

### Full recovery (recommended)

```bash
python piano_recovery.py ./locked --out ./recovered
```

This runs all 6 stages:
1. Discover `.locked` files
2. Decrypt each file + extract vault password
3. Detect real file types and rename extensions
4. Read backup config & SQLite database
5. Restore original filenames into organized folders
6. Embed EXIF metadata and set file timestamps

### Options

```bash
# Preview filename restoration without making changes
python piano_recovery.py ./locked --out ./recovered --dry-run

# Only decrypt files, skip filename restoration
python piano_recovery.py ./locked --out ./recovered --decrypt-only

# Skip decryption, only restore filenames (files already decrypted)
python piano_recovery.py ./locked --out ./recovered --skip-decrypt

# Disable EXIF metadata injection
python piano_recovery.py ./locked --out ./recovered --no-exif
```

> **Note (Windows):** If you see Unicode errors, prefix with: `$env:PYTHONIOENCODING="utf-8"`

## Output Structure

```
recovered/
├── My Pictures/
│   ├── IMG-20260818-WA0056.jpg    ← Original filename restored
│   ├── IMG-20260818-WA0058.jpg
│   └── ...
├── My Videos/
│   ├── VID-20260825-WA0022.mp4
│   └── VID-20260825-WA0026.mp4
├── backup.zip                      ← Decrypted backup archive
└── recovery_report.txt             ← Full metadata report
```

## Project Structure

```
piano-vault-recovery/
├── piano_recovery.py    ← Main unified recovery script
├── docs/
│   └── workflow.md      ← Detailed reverse-engineering workflow
├── legacy/              ← Older scripts (before unification)
│   ├── recovery.py      
│   ├── recovery_all.py  
│   └── rename_from_db.py
├── README.md
├── requirements.txt
└── .gitignore
```

## Reverse Engineering Methodology

The encryption parameters were recovered through:

1. **APK decompilation** with `jadx` — identified `Crypto.java` as the core encryption class using Google Tink
2. **Smali analysis** with `apktool` — traced native method declarations
3. **Native library analysis** with `Ghidra` — extracted hardcoded AES keys, AAD string (`@Secret(|)Piano@`), and Tink keyset configurations from `libPiano.so`

Key findings:
- **Streaming encryption:** `AesGcmHkdfStreamingKey` with 128-bit key, 1MB segments
- **Password encryption:** `AesGcmKey` with 128-bit key
- **Keys stored in:** Native C++ `Security` class inside `libPiano.so`
- **AAD/Embed key:** `@Secret(|)Piano@`
- **Backdoor code:** Entering `112233` on the piano triggers password recovery

See [`docs/workflow.md`](docs/workflow.md) for the complete reverse-engineering narrative.

## License

MIT License — see [LICENSE](LICENSE) for details.
