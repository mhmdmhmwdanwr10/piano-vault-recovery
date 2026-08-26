import sys
import subprocess
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
RECOVERY_SCRIPT = BASE_DIR / "recovery.py"


def detect_file_type(path: Path):
    """
    Detect common file formats from magic bytes.
    Returns (extension, description) or (None, "Unknown").
    """
    try:
        with open(path, "rb") as f:
            data = f.read(4096)
    except Exception as e:
        return None, f"Read error: {e}"

    # Images
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

    # MP4 / MOV / ISO Base Media
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12]

        if brand in (
            b"qt  ",
        ):
            return ".mov", "QuickTime video"

        return ".mp4", "MP4 / ISO Base Media"

    # Matroska / WebM
    if data.startswith(b"\x1A\x45\xDF\xA3"):
        if b"webm" in data.lower():
            return ".webm", "WebM video"
        return ".mkv", "Matroska video"

    # Audio
    if data.startswith(b"ID3"):
        return ".mp3", "MP3 audio"

    if len(data) >= 2 and data[:2] == b"\xFF\xFB":
        return ".mp3", "MP3 audio"

    if len(data) >= 2 and data[:2] == b"\xFF\xF3":
        return ".mp3", "MP3 audio"

    if len(data) >= 2 and data[:2] == b"\xFF\xF2":
        return ".mp3", "MP3 audio"

    if data.startswith(b"OggS"):
        return ".ogg", "Ogg media"

    if data.startswith(b"fLaC"):
        return ".flac", "FLAC audio"

    # Documents
    if data.startswith(b"%PDF-"):
        return ".pdf", "PDF document"

    # ZIP-based formats
    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06") or data.startswith(b"PK\x07\x08"):

        # Check for Office formats
        try:
            import zipfile

            with zipfile.ZipFile(path, "r") as z:
                names = z.namelist()

                if any(name.startswith("word/") for name in names):
                    return ".docx", "Word document"

                if any(name.startswith("xl/") for name in names):
                    return ".xlsx", "Excel spreadsheet"

                if any(name.startswith("ppt/") for name in names):
                    return ".pptx", "PowerPoint presentation"

        except Exception:
            pass

        return ".zip", "ZIP archive"

    # Android APK is also ZIP, but if META-INF + AndroidManifest.xml exist
    # the above ZIP check may not distinguish it without deeper inspection.

    # GZIP
    if data.startswith(b"\x1F\x8B\x08"):
        return ".gz", "GZIP archive"

    # RAR
    if data.startswith(b"Rar!\x1A\x07\x00"):
        return ".rar", "RAR archive"

    if data.startswith(b"Rar!\x1A\x07\x01\x00"):
        return ".rar", "RAR archive"

    # 7z
    if data.startswith(b"7z\xBC\xAF\x27\x1C"):
        return ".7z", "7-Zip archive"

    # SQLite database
    if data.startswith(b"SQLite format 3\x00"):
        return ".db", "SQLite database"

    # ELF binary
    if data.startswith(b"\x7FELF"):
        return ".elf", "ELF binary"

    # Windows executable
    if data.startswith(b"MZ"):
        return ".exe", "Windows executable"

    # Plain text heuristic
    if data:
        try:
            text = data.decode("utf-8")
            printable = sum(
                1 for c in text
                if c.isprintable() or c in "\r\n\t"
            )

            if len(text) > 0 and printable / len(text) > 0.95:
                return ".txt", "Text file"
        except UnicodeDecodeError:
            pass

    return None, "Unknown"


def get_unique_path(path: Path):
    """Avoid overwriting an existing file."""
    if not path.exists():
        return path

    counter = 1

    while True:
        candidate = path.with_name(
            f"{path.stem}_{counter}{path.suffix}"
        )

        if not candidate.exists():
            return candidate

        counter += 1


def rename_recovered_files(output_dir: Path):
    """
    Finds *.recovered files and renames them according to their detected type.
    """
    recovered_files = sorted(output_dir.rglob("*.recovered"))

    print()
    print("Detecting recovered file types")
    print("==============================")

    if not recovered_files:
        print("No .recovered files found.")
        return

    known = 0
    unknown = 0

    for file_path in recovered_files:
        extension, description = detect_file_type(file_path)

        if extension is None:
            print(f"[?] {file_path.name}")
            print(f"    Unknown format - keeping .recovered")
            unknown += 1
            continue

        new_path = file_path.with_suffix(extension)
        new_path = get_unique_path(new_path)

        try:
            file_path.rename(new_path)

            print(f"[OK] {file_path.name}")
            print(f"     -> {new_path.name}")
            print(f"     Type: {description}")

            known += 1

        except Exception as e:
            print(f"[!] Could not rename {file_path.name}: {e}")
            unknown += 1

    print()
    print(f"Recognized: {known}")
    print(f"Unknown:    {unknown}")


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print(
            "  python recovery_all.py "
            "<locked_folder> --out <output_folder>"
        )
        sys.exit(1)

    input_dir = Path(sys.argv[1]).resolve()

    output_dir = (Path.cwd() / "recovered").resolve()

    if "--out" in sys.argv:
        index = sys.argv.index("--out")

        if index + 1 >= len(sys.argv):
            print("ERROR: --out requires a folder path.")
            sys.exit(1)

        output_dir = Path(sys.argv[index + 1]).resolve()

    if not input_dir.exists() or not input_dir.is_dir():
        print(f"ERROR: Input folder not found: {input_dir}")
        sys.exit(1)

    if not RECOVERY_SCRIPT.exists():
        print(f"ERROR: recovery.py not found:")
        print(f"       {RECOVERY_SCRIPT}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    locked_files = sorted(input_dir.rglob("*.locked"))

    print("Piano Vault Batch Recovery")
    print("==========================")
    print(f"Input:  {input_dir}")
    print(f"Output: {output_dir}")
    print(f"Files:  {len(locked_files)}")
    print()

    if not locked_files:
        print("No .locked files found.")
        sys.exit(0)

    processed = 0

    for index, file_path in enumerate(locked_files, 1):
        print()
        print("=" * 65)
        print(f"[{index}/{len(locked_files)}] Decrypting: {file_path.name}")
        print("=" * 65)

        subprocess.run(
            [
                sys.executable,
                str(RECOVERY_SCRIPT),
                str(file_path),
                "--out",
                str(output_dir),
            ],
            check=False,
        )

        processed += 1

    print()
    print("Batch decryption finished.")
    print(f"Processed: {processed}/{len(locked_files)}")

    # Automatically detect and rename every successfully recovered file
    rename_recovered_files(output_dir)


if __name__ == "__main__":
    main()