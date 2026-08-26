import argparse
import struct
import sys
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
except ImportError:
    print("Missing dependency: cryptography")
    print("Install it with:")
    print("python -m pip install cryptography")
    sys.exit(2)


# ============================================================
# Piano Vault parameters recovered from libPiano.so
# ============================================================

STREAM_KEY = bytes.fromhex(
    "29d3b7ff1be51f73b1ca82b53081b820"
)

PASSWORD_KEY = bytes.fromhex(
    "763022eeb50a28b41599d61a1affcedb"
)

AAD = b"@Secret(|)Piano@"


# ============================================================
# Tink AesGcmHkdfStreaming parameters
# ============================================================

SEGMENT_SIZE = 1048576       # 1 MiB
DERIVED_KEY_SIZE = 16
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 7

# header = 1 byte length + 16 byte salt + 7 byte nonce prefix
HEADER_SIZE = (
    1
    + DERIVED_KEY_SIZE
    + NONCE_PREFIX_SIZE
)

# Verified from the actual large file.
FIRST_SEGMENT_OFFSET = 0


# ============================================================
# File header
# ============================================================

WEBP_HEADER_SIZE = 246
PASSWORD_BLOCK_SIZE = 200
FULL_APP_HEADER_SIZE = 446


def looks_like_webp_prefix(data: bytes) -> bool:
    return (
        len(data) >= 12
        and data[:4] == b"RIFF"
        and data[8:12] == b"WEBP"
    )


def locate_streaming_offset(data: bytes) -> int:
    """
    Piano Vault layouts:

        246 bytes:
            WebP dummy header
            StreamingAead starts immediately

    OR

        446 bytes:
            WebP dummy header
            200-byte password block
            StreamingAead starts here
    """

    candidates = (
        FULL_APP_HEADER_SIZE,
        WEBP_HEADER_SIZE,
    )

    for offset in candidates:

        if len(data) < offset + HEADER_SIZE:
            continue

        # Tink header length for 16-byte derived key:
        # 1 + 16 + 7 = 24
        if data[offset] == HEADER_SIZE:
            return offset

    raise ValueError(
        "Could not locate Tink StreamingAead header "
        "at offset 446 or 246."
    )


# ============================================================
# Tink header
# ============================================================

def parse_stream_header(stream_data: bytes):
    if len(stream_data) < HEADER_SIZE:
        raise ValueError(
            "Streaming data is shorter than its header."
        )

    header_length = stream_data[0]

    if header_length != HEADER_SIZE:
        raise ValueError(
            f"Unexpected Tink header length: "
            f"{header_length}; expected {HEADER_SIZE}."
        )

    salt = stream_data[
        1:
        1 + DERIVED_KEY_SIZE
    ]

    nonce_prefix = stream_data[
        1 + DERIVED_KEY_SIZE:
        HEADER_SIZE
    ]

    return salt, nonce_prefix


# ============================================================
# HKDF
# ============================================================

def derive_stream_key(salt: bytes) -> bytes:

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_SIZE,
        salt=salt,
        info=AAD,
    )

    return hkdf.derive(
        STREAM_KEY
    )


# ============================================================
# Tink nonce
# ============================================================

def make_nonce(
    nonce_prefix: bytes,
    segment_number: int,
    is_last: bool,
) -> bytes:

    return (
        nonce_prefix
        + struct.pack(
            ">I",
            segment_number
        )
        + bytes([
            1 if is_last else 0
        ])
    )


# ============================================================
# Streaming decrypt
# ============================================================

def decrypt_stream(
    stream_data: bytes
) -> bytes:

    salt, nonce_prefix = parse_stream_header(
        stream_data
    )

    derived_key = derive_stream_key(
        salt
    )

    aes = AESGCM(
        derived_key
    )

    ciphertext = stream_data[
        HEADER_SIZE:
    ]

    if len(ciphertext) < TAG_SIZE:
        raise ValueError(
            "Ciphertext is too short."
        )

    plaintext = bytearray()

    # --------------------------------------------------------
    # IMPORTANT:
    #
    # Tink's first segment is:
    #
    #   ciphertextSegmentSize
    #   - headerLength
    #   - firstSegmentOffset
    #
    # With this app:
    #
    #   1,048,576 - 24 - 0
    #   = 1,048,552
    # --------------------------------------------------------

    first_segment_length = (
        SEGMENT_SIZE
        - HEADER_SIZE
        - FIRST_SEGMENT_OFFSET
    )

    pos = 0
    segment_number = 0

    while pos < len(ciphertext):

        if segment_number == 0:

            segment_length = min(
                first_segment_length,
                len(ciphertext) - pos
            )

        else:

            segment_length = min(
                SEGMENT_SIZE,
                len(ciphertext) - pos
            )

        segment = ciphertext[
            pos:
            pos + segment_length
        ]

        is_last = (
            pos + segment_length
            == len(ciphertext)
        )

        if len(segment) < TAG_SIZE:
            raise ValueError(
                f"Segment {segment_number} "
                "is shorter than the GCM tag."
            )

        nonce = make_nonce(
            nonce_prefix,
            segment_number,
            is_last
        )

        try:

            # IMPORTANT:
            # AAD is used as HKDF info.
            # It is NOT supplied separately to AES-GCM.
            part = aes.decrypt(
                nonce,
                segment,
                None
            )

        except Exception as exc:

            raise ValueError(
                "GCM authentication failed on "
                f"segment {segment_number}."
            ) from exc

        plaintext.extend(
            part
        )

        pos += segment_length
        segment_number += 1

    return bytes(
        plaintext
    )


# ============================================================
# Recover one file
# ============================================================

def recover_file(
    input_path: Path,
    output_dir: Path
):

    data = input_path.read_bytes()

    if not looks_like_webp_prefix(data):

        raise ValueError(
            "Invalid Piano Vault file: "
            "RIFF/WEBP header not found."
        )

    stream_offset = locate_streaming_offset(
        data
    )

    print(
        f"    Detected streaming offset: "
        f"{stream_offset}"
    )

    stream_data = data[
        stream_offset:
    ]

    salt, nonce_prefix = parse_stream_header(
        stream_data
    )

    print(
        f"    Segment size: "
        f"{SEGMENT_SIZE}"
    )

    print(
        f"    First segment size: "
        f"{SEGMENT_SIZE - HEADER_SIZE - FIRST_SEGMENT_OFFSET}"
    )

    print(
        f"    Salt: {salt.hex()}"
    )

    print(
        f"    Nonce prefix: "
        f"{nonce_prefix.hex()}"
    )

    plaintext = decrypt_stream(
        stream_data
    )

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_path = (
        output_dir
        / f"{input_path.stem}.recovered"
    )

    output_path.write_bytes(
        plaintext
    )

    return (
        stream_offset,
        output_path,
        len(plaintext)
    )


# ============================================================
# Main
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Recover Piano Vault .locked files"
        )
    )

    parser.add_argument(
        "input",
        help=(
            "A .locked file or directory "
            "containing .locked files"
        )
    )

    parser.add_argument(
        "--out",
        default="recovered",
        help=(
            "Output directory "
            "(default: recovered)"
        )
    )

    args = parser.parse_args()

    input_path = Path(
        args.input
    )

    output_dir = Path(
        args.out
    )

    if input_path.is_file():

        files = [
            input_path
        ]

    elif input_path.is_dir():

        files = sorted(
            input_path.glob(
                "*.locked"
            )
        )

    else:

        print(
            f"Not found: {input_path}"
        )

        return 1

    if not files:

        print(
            "No .locked files found."
        )

        return 1

    print(
        "Piano Vault Recovery"
    )

    print(
        "===================="
    )

    print(
        f"Files: {len(files)}"
    )

    print()

    success = 0

    for path in files:

        print(
            f"[+] {path.name}"
        )

        try:

            (
                offset,
                output,
                size
            ) = recover_file(
                path,
                output_dir
            )

            print(
                f"    OK"
                f" | streaming offset: {offset}"
                f" | recovered: {size} bytes"
            )

            print(
                f"    -> {output}"
            )

            success += 1

        except Exception as exc:

            print(
                f"    FAILED: {exc}"
            )

        print()

    print(
        f"Done: {success}/{len(files)} recovered."
    )

    return (
        0
        if success == len(files)
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )