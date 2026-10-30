# IDA-Plugin-Strings-decryptor-Anogs 🐾

Comprehensive string decryptor plugin for **IDA Pro** (tested on IDA Pro 7.x, 8.x, and 9.2).  
Designed for automatic detection, extraction, and decryption of obfuscated strings in the **Tencent Anogs / ACE (Anti-Cheat Expert / TSS)** binary libraries used in mobile games (including **PUBG Mobile Global Version**).

Supports both major architectures:
- **ARM 32-bit (armeabi-v7a)** — preconfigured profiles for PUBG Mobile 4.0 and 4.1.
- **ARM 64-bit (arm64-v8a)** — full-featured engine with automatic detection of target accessor functions and string table RVA (`.rodata`) (tested on PUBG Mobile 4.6).

---

## 🌟 Key Features

1. **Automatic Architecture & Version Detection**:
   - The master script `DecryptStringsAuto.py` automatically detects the bitness of the active IDB (32-bit vs 64-bit) and the game version, routing execution to the corresponding engine module.
2. **Heuristic Analysis of Decryptor Functions**:
   - Automated identification of decryptor wrapper functions by traversing cross-reference (xref) graphs to target accessor stubs.
   - Machine code pattern matching (ARM / ARM64) to extract algorithm parameters dynamically: rolling key `xor_key` (via `EOR` instructions) and iteration step `delta` (via `ADDS` / `ADD` instructions).
3. **Call Argument Parsing**:
   - **ARM32**: decodes immediate offset arguments passed via register `R0` across `MOV`, `MOVW`, and `MOVT` instruction sequences.
   - **ARM64**: decodes `W0`/`X0` argument loading across `MOV`, `MOVZ`, `MOVN`, `ORR`, and zero registers `WZR`/`XZR`.
4. **Hex-Rays Decompiler Integration**:
   - Injects decrypted strings as inline comments directly into disassembly listings.
   - High-performance batched commenting in Hex-Rays pseudocode without decompilation slowdowns.
5. **Detailed Dumps & Reports**:
   - Automatically exports decrypted strings to formatted human-readable `.txt` tables and structured `.json` datasets with full call site telemetry.

---

## 📁 Repository Structure

```
IDA-Plugin-Strings-decryptor-Anogs/
├── DecryptStringsAuto.py           # 🚀 Master universal entry point with auto-detection
│
├── plugins/                        # 🧩 Architecture-specific decryptor modules
│   ├── arm32/                      # 🔹 32-bit ARM (armeabi-v7a)
│   │   ├── DecPubg4.1Strings.py    # Plugin for PUBG Mobile 4.1 (ARM32)
│   │   └── DecPubg4.0Strings.py    # Plugin for PUBG Mobile 4.0 (ARM32)
│   └── arm64/                      # 🔹 64-bit ARM (arm64-v8a)
│       └── DecAnogsArm64Strings.py  # Plugin for ARM64 with auto-detect of TARGETS & table RVA
│
├── dumps/                          # 📄 Decrypted strings tables and call telemetry
│   ├── arm32/
│   │   ├── Pubg 4.1 Decrypted.txt  # 3,175 call sites, 100 decryptors (PUBG 4.1)
│   │   └── Pubg 4.0 Decrypted.txt  # String dump for PUBG 4.0
│   └── arm64/
│       ├── Pubg Decrypted ARM64.txt   # 3,199 call sites, 2,087 unique strings (ARM64)
│       ├── Pubg Decrypted ARM64.json  # Complete structured JSON dataset
│       ├── decrypted_strings.txt      # Latest dump from active IDB
│       └── decrypted_strings.json     # Latest structured JSON dump
│
├── .gitignore
├── LICENSE                         # MIT License
└── README.md
```

---

## 🚀 Usage

### Method 1: Universal Auto-Runner (Recommended)
1. Open the target `libanogs.so` binary in **IDA Pro** (either 32-bit or 64-bit IDA).
2. Wait until auto-analysis completes.
3. In the top menu, navigate to:  
   `File` → `Script file...` (or press `Alt + F7`).
4. Select **`DecryptStringsAuto.py`** from the repository root.
5. The script will automatically detect the binary architecture and version, decrypt all strings, and apply comments to both assembly and Hex-Rays pseudocode!

### Method 2: Running a Specific Script
You can directly run any architecture-specific script from the `plugins/` folder:
- For 32-bit PUBG Mobile 4.1: `plugins/arm32/DecPubg4.1Strings.py`
- For 32-bit PUBG Mobile 4.0: `plugins/arm32/DecPubg4.0Strings.py`
- For 64-bit Anogs (v8a): `plugins/arm64/DecAnogsArm64Strings.py`

---

## 🔬 Anogs String Encryption Algorithm

Encrypted strings are stored in a contiguous pool at `Base + STRING_ARRAY_RVA + Offset`:

1. `Byte[0]` — Single-byte seed key `k0`.
2. `Byte[1]` — Encrypted string length:
   ```python
   length = byte[1] ^ k0
   ```
3. `Byte[2 .. Length + 1]` — Ciphertext bytes. Decrypted byte-by-byte with a rolling key:
   ```python
   k = k0
   for j in range(length):
       plain[j] = cipher[j] ^ k
       k = (((k + j) & 0xFF) ^ xor_key)
       k = (k + delta) & 0xFF
   ```
4. `Byte[Length + 2]` — Verification checksum byte:
   ```python
   (check_byte ^ k0) == (plain[0] ^ plain[1] ^ ... ^ plain[length - 1])
   ```

---

## 🔄 Updating for Newer Game Versions

When adapting the plugin to a newer game update:

### For ARM64:
`plugins/arm64/DecAnogsArm64Strings.py` features **automatic target accessor detection** and extracts `STRING_ARRAY_RVA` directly from `ADR` / `ADRL` assembly instructions!  
If needed, you can override constants manually at the top of the file:
```python
TARGETS = ["sub_XXXXXX", "sub_YYYYYY"]
STRING_ARRAY_RVA = 0xXXXXX
```

### For ARM32:
In `plugins/arm32/DecPubg4.XStrings.py`, update the following constants:
- `TARGETS` — names or addresses of the two target accessor functions.
- `STRING_ARRAY_RVA` — RVA of the encrypted string table in the data segment.
- `PARTIAL_KEY_RVA` — RVA of the auxiliary key table.

---

## 📬 Contact & Collaboration

For questions, updates, or collaboration:
- **Telegram**: [@ReverseEng1neer](https://t.me/ReverseEng1neer)
- **GitHub**: [pIat0n](https://github.com/pIat0n)
