# Advanced Password Cracker

A versatile tool for recovering passwords from various encrypted file formats using multiple attack strategies.

## Repository

This tool is part of the CyberSec-Toolkit collection:
https://github.com/Amr-Khaled-Ahmed/CyberSec-Toolkit/tree/main/Utility%20Tools/file%20cracker

## Features

- **Multi-format Support**: Handles various encrypted file formats including:
  - Archive files: ZIP, RAR (including RAR5), 7z
  - Documents: PDF, Office files (DOCX, XLSX, PPTX, DOC)
  - Encryption formats: AES, DES/DES3, GPG

- **Multiple Attack Strategies**:
  - Brute-force attack (all possible combinations)
  - Dictionary attack (wordlist-based)
  - Hybrid attack (wordlist with common mutations)

- **Customizable Options**:
  - Character set selection for brute-force attacks
  - Adjustable password length ranges
  - Custom wordlist support

- **User-Friendly Features**:
  - Progress tracking with estimated completion time
  - Session resume capability
  - Graceful interruption handling
  - File type auto-detection

## Command-Line Options

| Option | Long Option | Description | Example |
|--------|-------------|-------------|---------|
| (positional) | file | Path to the encrypted file | `python password_cracker.py file.zip` |
| `-t` | `--type` | Specify file type (bypass auto-detection) | `-t pdf` |
| `-w` | `--wordlist` | Path to wordlist file for dictionary attack | `-w rockyou.txt` |
| `-m` | `--min` | Minimum password length | `-m 4` |
| `-M` | `--max` | Maximum password length | `-M 8` |
| `-c` | `--charset` | Custom character set | `-c "abc123"` |
| `-h` | `--help` | Show help message | `-h` |

## Supported File Types

| File Type | Extensions | Description |
|-----------|------------|-------------|
| ZIP | .zip | Standard ZIP archives |
| RAR | .rar | RAR archives (versions 4 and below) |
| RAR5 | .rar | RAR version 5 archives |
| 7z | .7z | 7-Zip archives |
| PDF | .pdf | PDF documents |
| Office | .docx, .xlsx, .pptx, .doc | Microsoft Office documents |
| AES | .aes, .enc | AES encrypted files |
| DES/DES3 | .des | DES/Triple DES encrypted files |
| GPG | .gpg, .pgp | GPG encrypted files |

## Character Set Options

| Option | Characters | Example |
|--------|------------|---------|
| 1 | Lowercase letters (a-z) | abcdefghijklmnopqrstuvwxyz |
| 2 | Uppercase letters (A-Z) | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| 3 | Letters (a-z, A-Z) | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ |
| 4 | Letters + Digits | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 |
| 5 | Letters + Digits + Symbols | abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+ |
| 6 | Lowercase + Digits | abcdefghijklmnopqrstuvwxyz0123456789 |
| 7 | Uppercase + Digits | ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 |
| 8 | Hexadecimal (0-9, a-f) | 0123456789abcdef |
| 9 | Numeric (0-9) | 0123456789 |
| 10 | Custom characters | (user-defined) |

## Installation

### Prerequisites

```bash
pip install tqdm zipfile rarfile py7zr pikepdf msoffcrypto-tool pycryptodome patool pdfplumber
```

Some packages might require additional system dependencies:
- `rarfile` requires the `unrar` utility
- `patool` might require additional utilities based on archive types
- `gpg` requires the GPG command-line tool

### Clone the Repository

```bash
git clone https://github.com/Amr-Khaled-Ahmed/CyberSec-Toolkit.git
cd "CyberSec-Toolkit/Utility Tools/file cracker"
```

## Usage

### Basic Usage

```bash
python password_cracker.py /path/to/encrypted/file
```

This will prompt you for attack mode and necessary options.

### Detailed Usage Guide

1. **Run the script**:
   ```bash
   python password_cracker.py
   ```

2. **Provide the file path** when prompted:
   ```
   Enter path to password-protected file: example.zip
   ```

3. **Select an attack mode**:
   ```
   Select attack mode:
   1. Brute-force (all possible combinations)
   2. Dictionary attack (wordlist)
   3. Hybrid attack (wordlist + mutations)
   Enter your choice (1-3): 1
   ```

4. **For brute-force attack**:
   - Select a character set:
     ```
     Choose character set:
     1. Lowercase letters (a-z)
     2. Uppercase letters (A-Z)
     3. Letters (a-z, A-Z)
     4. Letters + Digits
     5. Letters + Digits + Symbols
     6. Lowercase + Digits
     7. Uppercase + Digits
     8. Hexadecimal (0-9, a-f)
     9. Numeric (0-9)
     10. Custom characters
     Enter your choice (1-10): 6
     ```
   - Enter minimum and maximum password lengths:
     ```
     Minimum password length: 4
     Maximum password length: 6
     ```

5. **For dictionary attack**:
   - Provide path to wordlist:
     ```
     Enter path to wordlist file: wordlists/rockyou.txt
     ```

### Expected Output

The tool displays progress and results in the terminal:

1. **Starting the attack**:
   ```
   [*] Starting attack on example.zip [ZIP]
   [i] Character set size: 36
   [i] Estimated time: ~5.2 minutes
   ```

2. **Progress bar during operation**:
   ```
   Testing passwords:  45%|█████████     | 1215478/2701500 [01:32<01:53, 13021.8pwd/s] Current: a93bc...
   ```

3. **Successful password recovery**:
   ```
   [+] Password found: p4ssw0rd
   [i] Attempts: 15234
   [i] Time taken: 123.45 seconds
   [+] Successfully cracked the password!
   ```

4. **Unsuccessful attempt**:
   ```
   [-] Password not found.
   [i] Total attempts: 2701500
   [i] Time taken: 207.31 seconds
   [-] Failed to crack the password with the given parameters.
   ```

5. **Interrupted operation** (when pressing Ctrl+C):
   ```
   [!] Stopping brute-force process...
   [i] Total attempts: 1215478
   [i] Time taken: 92.87 seconds
   ```

### Command-line Examples

#### Brute-force Attack
```bash
python password_cracker.py encrypted.zip -m 4 -M 6 -c "abcdefghijklmnopqrstuvwxyz0123456789"
```

#### Dictionary Attack
```bash
python password_cracker.py protected.pdf -w /path/to/wordlist.txt
```

#### Using with Specific File Type
```bash
python password_cracker.py mysterious_file -t pdf -w /path/to/wordlist.txt
```

## Attack Modes

### 1. Brute-force Attack
Tests all possible combinations of characters from the specified character set and length range. This is thorough but can be time-consuming for longer passwords.

### 2. Dictionary Attack
Tests passwords from a provided wordlist. Much faster than brute-force if the password is common or known to be in the list.

### 3. Hybrid Attack
Combines dictionary words with common mutations (adding numbers, special characters, capitalization, etc.). Balances speed and coverage.

## Limitations

- Performance depends on your hardware and the complexity of the encryption
- Some file formats may have additional protection mechanisms that limit brute-force attempts
- RAR5 and some other formats are particularly slow to test passwords against

## Security Notes

This tool is intended for legitimate password recovery of your own files. Using it to access files without authorization is illegal and unethical. The authors take no responsibility for misuse of this software.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
