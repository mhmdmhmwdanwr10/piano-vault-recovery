# Piano Vault Recovery — Complete Analysis & Automated Recovery Pipeline

> This document records the practical workflow, findings, problems, fixes, and the final plan to merge the recovery scripts into one automated pipeline.

---

## 1. Objective

The goal was to recover files encrypted by the Piano Vault / Piano Native Android application and restore them as automatically as possible.

The final desired workflow is:

```text
Encrypted application files (.locked)
        ↓
Automatic batch decryption
        ↓
Automatic file-type detection
        ↓
Recover backup ZIP
        ↓
Read SQLite database inside backup
        ↓
Match recovered files to database entries
        ↓
Restore original filenames
        ↓
Final recovered folder
```

The user explicitly preferred automation over manual work, so the solution evolved from manual Ghidra investigation into an automated Python pipeline.

---

# 2. Reverse-engineering and Ghidra investigation

## 2.1 Initial target

The native library under investigation was:

```text
libPiano.so
```

The Ghidra project was:

```text
C:\Users\AL WALEED\Desktop\piano\ghidra_project
```

Project name:

```text
PianoNative
```

Important native strings and symbols identified during investigation included references such as:

```text
primaryKeyId
keyData
AesGcmKey
AesGcmHkdfStreamingKey
Secret / Piano-related constants
```

The native code indicated that the application was using cryptographic code related to Tink-style AES-GCM/HKDF streaming encryption.

---

## 2.2 Ghidra headless automation problems

The first attempt to run:

```powershell
.\analyzeHeadless.bat ...
```

failed because PowerShell was running from:

```text
C:\Windows\system32
```

and `analyzeHeadless.bat` was not in that directory.

After changing into the Ghidra support directory, another issue appeared:

```text
"C:\Users\AL WALEED\Desktop\piano\launch.bat" is not recognized
```

The working solution was to call Ghidra's launcher explicitly:

```powershell
& "C:\ghidra\ghidra_10.0.1_PUBLIC\support\launch.bat" fg Ghidra-Headless 2G "-XX:ParallelGCThreads=2 -XX:CICompilerCount=2" ghidra.app.util.headless.AnalyzeHeadless "C:\Users\AL WALEED\Desktop\piano\ghidra_project" PianoNative -process libPiano.so -postScript analyze_piano
```

The analysis then succeeded.

Important successful output:

```text
Piano analysis completed.
Report: C:\Users\AL WALEED\Desktop\piano\piano_native_report.txt
```

One previous problem was that Ghidra could not find the script when it was supplied as a full path. The working form was to place the script in a Ghidra script directory and call it by script name:

```text
-postScript analyze_piano
```

rather than relying on an arbitrary full filesystem path.

---

# 3. Encryption format findings

The recovery work established several important facts.

## 3.1 Files are encrypted individually

The application does not necessarily place all protected user files inside one encrypted container.

Each file is stored as an individual file with a name similar to:

```text
doNotDelete_important_<UUID>.<identifier>.locked
```

Examples:

```text
doNotDelete_important_212034b0-7a87-4439-82ad-9366a7d22534.6d7034.locked
doNotDelete_important_5192c42e-8fc8-4cd5-bdaf-f13581a0e10c.6a7067.locked
```

The UUID-like portion is important because it is later used by the application's database to map the encrypted storage file back to metadata and/or an original filename.

---

## 3.2 Backup file

The file:

```text
backup.locked
```

was successfully decrypted.

The recovered file was identified as:

```text
backup.recovered → backup.zip
```

The ZIP archive contained a SQLite database file named:

```text
db
```

The database is important because it contains the mapping information for the protected files.

The successful recovery therefore demonstrated that the backup file is not simply a normal media file; it is an encrypted backup archive containing application metadata.

---

# 4. Recovery implementation

## 4.1 Streaming encryption parameters

The successful recovery output showed values such as:

```text
Streaming offset: 446
Segment size: 1048576
First segment size: 1048552
```

The encrypted media files generally used a detected streaming offset of:

```text
446
```

The backup file used a different offset:

```text
246
```

This difference is important. The recovery tool therefore must not blindly assume that every file begins streaming ciphertext at the same position.

The working decryptor detects the appropriate streaming offset and uses the correct framing before decrypting the file.

---

## 4.2 Successful recovery result

The batch recovery successfully processed:

```text
11/11 files
```

The recovered results included:

- `backup.zip`
- 2 MP4 files
- 8 JPEG images

All 11 recovered files were recognized successfully.

No unknown file types remained.

---

# 5. Automatic file type detection

The decrypted files initially had names ending in:

```text
.recovered
```

This was inconvenient because the actual file type was unknown from the filename alone.

A file-type detection stage was added to inspect the recovered file contents and rename the extension automatically.

Examples:

```text
xxxxx.recovered → xxxxx.mp4
xxxxx.recovered → xxxxx.jpg
xxxxx.recovered → xxxxx.zip
```

The successful output demonstrated:

```text
backup.recovered → backup.zip
Type: ZIP archive
```

and:

```text
...6d7034.recovered → ...6d7034.mp4
Type: MP4 / ISO Base Media
```

and:

```text
...6a7067.recovered → ...6a7067.jpg
Type: JPEG image
```

This removed the need to manually inspect each recovered file.

---

# 6. Database-based filename restoration

## 6.1 Why the filenames still looked wrong

Even after decryption and file-type detection, the filenames were still application-generated names such as:

```text
doNotDelete_important_5192c42e-8fc8-4cd5-bdaf-f13581a0e10c.6a7067.jpg
```

The plan was to use the recovered backup ZIP and the SQLite database inside it to restore the original filenames.

The database was successfully detected and reported:

```text
db: 11 filename mapping(s)
Total mappings: 11
```

This strongly indicates that the database contains metadata corresponding to the 11 protected files.

---

## 6.2 First filename restoration problem

The first implementation looked for the database filename literally.

The database referenced names ending in:

```text
.locked
```

For example:

```text
doNotDelete_important_<UUID>.6a7067.locked
```

But after the recovery pipeline, the actual files had already been renamed to:

```text
doNotDelete_important_<UUID>.6a7067.jpg
```

or:

```text
doNotDelete_important_<UUID>.6d7034.mp4
```

Therefore the restoration script incorrectly reported all files as missing.

Example failure:

```text
Missing recovered file for:
doNotDelete_important_....locked
```

even though the corresponding `.jpg` or `.mp4` file existed.

---

## 6.3 Required fix

The matching logic must ignore the final `.locked` suffix and search for the same base name using any recovered extension.

Conceptually:

```text
Database:
doNotDelete_important_UUID.6a7067.locked

Recovered folder:
doNotDelete_important_UUID.6a7067.jpg
```

These must be treated as the same logical file.

A robust matching algorithm should:

1. Remove `.locked` from the database filename.
2. Search for:
   ```text
   <base>.*
   ```
3. Accept the existing file regardless of whether its extension is:
   - `.jpg`
   - `.jpeg`
   - `.mp4`
   - `.png`
   - `.pdf`
   - another detected type
4. Rename that physical recovered file to the original filename stored in the database while preserving or validating the real extension.

---

# 7. SQLite temporary-file problem

The filename restoration script also produced:

```text
PermissionError: [WinError 32]
The process cannot access the file because it is being used by another process
```

The problem occurred while Python was trying to delete the temporary extracted SQLite database.

The likely cause was that the SQLite connection remained open.

## Correct approach

The database should be opened with a context manager:

```python
with sqlite3.connect(db_path) as conn:
    cursor = conn.cursor()

    # Read mappings here.
```

This ensures that the connection is closed before Python attempts to remove the temporary directory.

Alternatively, an explicit:

```python
conn.close()
```

must occur before temporary-directory cleanup.

---

# 8. The three-script architecture

The work naturally evolved into three logical scripts.

## Script 1 — `recovery.py`

Purpose:

```text
Decrypt one .locked file
```

Responsibilities:

- Read encrypted file.
- Detect the correct streaming offset.
- Parse required encryption/framing information.
- Decrypt the streaming ciphertext.
- Write a `.recovered` file.

Example:

```powershell
python .\recovery\recovery.py ".\locked\backup.locked" --out ".\recovered"
```

---

## Script 2 — `recovery_all.py`

Purpose:

```text
Batch decrypt all .locked files
```

Responsibilities:

- Scan the input directory.
- Find all `.locked` files.
- Run recovery for each file.
- Save all recovered files.
- Detect file type.
- Rename extensions automatically.

Example:

```powershell
python .\recovery\recovery_all.py ".\locked" --out ".\recovered"
```

---

## Script 3 — `rename_from_db.py`

Purpose:

```text
Recover the backup database and restore original filenames
```

Responsibilities:

- Open recovered `backup.zip`.
- Extract the database.
- Read SQLite metadata.
- Build encrypted-name → original-name mappings.
- Match mappings against recovered files.
- Rename files automatically.

The corrected version must use extension-independent matching and must close the SQLite database before temporary cleanup.

---

# 9. Final integration plan — one automated pipeline

The preferred final solution is to merge the three scripts into one script, for example:

```text
piano_recovery.py
```

The user should only need to run one command.

## Input

```text
piano/
├── locked/
│   ├── backup.locked
│   ├── doNotDelete_important_....locked
│   └── ...
```

## Output

```text
piano/
├── recovered/
│   ├── original_file_name.jpg
│   ├── original_video_name.mp4
│   └── ...
├── backup/
│   ├── backup.zip
│   └── extracted database files
```

---

# 10. Final pipeline logic

The integrated script should execute the following stages.

## Stage 1 — Discover encrypted files

```text
locked/
    ↓
Find all *.locked
```

The script should count and display all discovered files.

---

## Stage 2 — Decrypt every file

For each file:

```text
.locked
    ↓
Detect framing / streaming offset
    ↓
Decrypt
    ↓
.recovered
```

The script should continue processing other files even if one file fails.

A summary should be printed:

```text
Successful: X
Failed:     Y
```

---

## Stage 3 — Detect real file types

For every successful `.recovered` output:

```text
Read magic bytes / signatures
    ↓
Determine type
    ↓
Rename extension
```

Examples:

```text
ZIP  → .zip
JPEG → .jpg
MP4  → .mp4
PNG  → .png
PDF  → .pdf
```

Unknown files should remain unchanged and be listed separately.

---

## Stage 4 — Locate the backup automatically

The script should automatically identify the recovered backup archive.

Preferred logic:

1. Look for a recovered file whose original encrypted name is `backup.locked`.
2. Confirm its signature is ZIP.
3. Use it as the metadata source.

The user should not need to manually provide `backup.recovered`.

---

## Stage 5 — Extract and inspect the backup

```text
backup.zip
    ↓
Extract to temporary directory
    ↓
Locate SQLite database(s)
```

The script should inspect archive contents and locate files that are valid SQLite databases.

---

## Stage 6 — Read filename mappings

For each SQLite database:

- Inspect tables.
- Locate fields containing protected/encrypted filenames.
- Locate fields containing original filenames.
- Build a mapping.

Conceptually:

```text
encrypted storage filename
        ↓
original user filename
```

The script should report how many mappings were found.

---

## Stage 7 — Match recovered files correctly

This is the important fix.

Given:

```text
Database:
file_UUID.6a7067.locked
```

the script should derive:

```text
file_UUID.6a7067
```

and search for:

```text
file_UUID.6a7067.*
```

It should not require the physical file to still end in `.locked`.

---

## Stage 8 — Restore original names

After a match is found:

```text
Application-generated recovered filename
        ↓
Original filename from database
```

The script should avoid overwriting existing files.

If the original filename already exists, it can generate a safe name such as:

```text
photo (1).jpg
photo (2).jpg
```

The final extension should preferably match the detected real file type.

---

# 11. Recommended command-line interface

The final integrated script should support a simple command:

```powershell
python .\piano_recovery.py ".\locked" --out ".\recovered"
```

The default behavior should:

1. Batch decrypt all `.locked` files.
2. Detect file types.
3. Recover and inspect the backup.
4. Read database mappings.
5. Restore original filenames.
6. Print a complete summary.

---

## Optional dry run

Before renaming anything:

```powershell
python .\piano_recovery.py ".\locked" --out ".\recovered" --dry-run
```

This should display:

```text
[DRY RUN]
old generated filename
    →
original filename
```

without changing files.

---

## Optional stage controls

For debugging, useful optional flags would be:

```text
--decrypt-only
--skip-decrypt
--skip-rename
--keep-temp
--dry-run
```

Examples:

```powershell
python .\piano_recovery.py ".\locked" --out ".\recovered" --decrypt-only
```

and:

```powershell
python .\piano_recovery.py ".\locked" --out ".\recovered" --skip-decrypt
```

The latter would be useful if all files were already decrypted and only filename restoration needed to be rerun.

---

# 12. Expected final output

A successful complete run should resemble:

```text
Piano Vault Recovery Pipeline
=============================

[1/4] Discovering encrypted files...
      Found: 11 files

[2/4] Decrypting files...
      OK: 11
      Failed: 0

[3/4] Detecting file types...
      ZIP: 1
      MP4: 2
      JPG: 8
      Unknown: 0

[4/4] Restoring original filenames...
      Backup database found
      Mappings found: 11
      Renamed: 10
      Backup retained: 1
      Missing: 0

=============================
Recovery complete.
Final files: C:\...\recovered
```

---

# 13. Important safety rules

1. Never modify or overwrite the original `.locked` files.
2. Keep the original encrypted folder as a backup.
3. Work only on copies or recovered outputs.
4. Do not overwrite an existing recovered file automatically.
5. Keep `backup.zip` because it contains important metadata.
6. Use `--dry-run` before performing the first real filename restoration.
7. Close SQLite connections before deleting temporary extraction directories.

---

# 14. Final conclusion

The major technical problems have been solved:

- Native application analysis was successfully automated through Ghidra headless mode.
- The encrypted streaming format was recovered sufficiently to decrypt the files.
- Both the backup and the protected media files were successfully decrypted.
- File-type detection correctly identified the recovered ZIP, MP4, and JPEG files.
- The backup contains a SQLite database with filename mappings.
- The remaining filename-restoration problem is not cryptographic; it is a matching issue caused by the recovered files changing from `.locked` to their real extensions.
- The final integrated pipeline should merge decryption, batch processing, file-type detection, backup inspection, SQLite mapping, and filename restoration into one command.

The final design therefore eliminates the manual workflow as much as possible:

```text
ONE COMMAND
    ↓
Decrypt everything
    ↓
Identify file types
    ↓
Read backup database
    ↓
Restore original names
    ↓
Produce final recovered files
```

# 15. Password Extraction and Metadata Embedding (Final Phase)

During the final phase of development, several new requirements were added to create a truly comprehensive recovery tool:

## 15.1 Password Extraction
**Problem:** The user wanted to retrieve the original vault password, not just decrypt the files.
**Solution:**
1. Analysis of `libPiano.so` revealed a `PASSWORD_KEY` (AES-128 key) and an associated data string (AAD) `@Secret(|)Piano@`.
2. In files with a 446-byte offset (instead of 246), the 200 bytes following the WebP header contained a password block encrypted with Tink AEAD (AES-GCM).
3. We implemented logic to parse the Tink AEAD prefix, extract the IV, ciphertext, and tag, and decrypt it using `AESGCM` from the `cryptography` library.
4. Additionally, we discovered that `backup.zip` contains a `config` file in JSON format that stores the plaintext password directly (`{"password":"123456"...}`).

## 15.2 SQLite Database Extraction & Organization
**Problem:** The database contained rich information including original file names, original paths on the device, file creation dates, and vault folder structures (e.g., 'My Pictures', 'My Videos').
**Solution:**
1. The script was updated to parse both `tbl_folder_info` and `tbl_file_info`.
2. Recovered files are now automatically sorted into subdirectories matching their vault folder names.
3. A detailed `recovery_report.txt` is generated alongside the recovered files, dumping all database metadata for forensic or organizational purposes.

## 15.3 File Type Matching Bug
**Problem:** The previous matching script looked for files with a `.recovered` extension to match against the DB. However, the batch script had already renamed them to `.jpg`, `.mp4`, etc.
**Solution:** The unified script now strips the `.locked` extension from the DB encrypted name and matches the base name against any file in the recovered directory, regardless of its current extension.

## 15.4 EXIF Metadata and Timestamps
**Problem:** Recovered files lost their original creation dates and paths.
**Solution:**
1. Added the `piexif` library to inject EXIF metadata into JPEG files.
2. The script extracts the date from WhatsApp-style filenames (e.g., `IMG-20260818-WA0056.jpg`) or falls back to the database `createDate`.
3. Sets the filesystem modification time (mtime) using `os.utime`.
4. Writes `DateTimeOriginal`, `DateTimeDigitized`, and stores the original device file path inside the `UserComment` EXIF tag.

## Final Output
The final tool, `piano_recovery.py`, successfully unifies decryption, batch processing, file detection, DB parsing, organization, and metadata injection into a single, fully automated command.

