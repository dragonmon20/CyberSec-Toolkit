import os
import time
import string
import signal
from itertools import product
from tqdm import tqdm
import zipfile
import rarfile
import py7zr
import pikepdf
import msoffcrypto
from Crypto.Cipher import AES, DES3, DES
from Crypto.Util.Padding import unpad
from io import BytesIO
import patoolib
import pdfplumber
import subprocess
import multiprocessing
import hashlib
import binascii
import argparse
import json
from typing import Optional, Generator, Callable, Dict, List

# Global flag for stopping the process
stop_flag = False
found_flag = False
current_password = ""
stats_file = "cracker_stats.json"

# Supported file types and their handlers
SUPPORTED_TYPES = {
    'zip': {'handler': 'archive', 'extensions': ['.zip']},
    'rar': {'handler': 'archive', 'extensions': ['.rar']},
    '7z': {'handler': 'archive', 'extensions': ['.7z']},
    'pdf': {'handler': 'pdf', 'extensions': ['.pdf']},
    'docx': {'handler': 'office', 'extensions': ['.docx', '.doc', '.xlsx', '.pptx']},
    'aes': {'handler': 'crypto', 'extensions': ['.aes', '.enc']},
    'des': {'handler': 'crypto', 'extensions': ['.des', '.des3']},
    'gpg': {'handler': 'gpg', 'extensions': ['.gpg', '.pgp']},
    'rar5': {'handler': 'archive', 'extensions': ['.rar']},  # RAR5 format
    'zipcrypto': {'handler': 'archive', 'extensions': ['.zip']},  # Traditional ZIP encryption
}

def signal_handler(sig: int, frame) -> None:
    """Handle interrupt signals to stop the process gracefully."""
    global stop_flag
    print("\n[!] Stopping brute-force process...")
    stop_flag = True
    save_stats()

def save_stats() -> None:
    """Save current cracking statistics to a file."""
    stats = {
        'last_password_tried': current_password,
        'timestamp': time.time()
    }
    with open(stats_file, 'w') as f:
        json.dump(stats, f)

def load_stats() -> Dict:
    """Load previous cracking statistics from file."""
    try:
        with open(stats_file, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

def get_file_type(file_path: str) -> Optional[str]:
    """Determine the file type based on extension and content."""
    ext = os.path.splitext(file_path)[1].lower()

    # First check by extension
    for file_type, info in SUPPORTED_TYPES.items():
        if ext in info['extensions']:
            return file_type

    # If extension doesn't match, try to detect by content
    try:
        if zipfile.is_zipfile(file_path):
            return 'zip'
        elif rarfile.is_rarfile(file_path):
            # Check if it's RAR5 format
            with open(file_path, 'rb') as f:
                header = f.read(8)
                if header.startswith(b'Rar!\x1a\x07\x01\x00'):
                    return 'rar5'
                else:
                    return 'rar'
    except:
        pass

    return None

def get_charset_from_user() -> str:
    """Prompt user to select a character set for brute-forcing."""
    print("\nChoose character set:")
    print("1. Lowercase letters (a-z)")
    print("2. Uppercase letters (A-Z)")
    print("3. Letters (a-z, A-Z)")
    print("4. Letters + Digits")
    print("5. Letters + Digits + Symbols")
    print("6. Lowercase + Digits")
    print("7. Uppercase + Digits")
    print("8. Hexadecimal (0-9, a-f)")
    print("9. Numeric (0-9)")
    print("10. Custom characters")

    choice = input("Enter your choice (1-10): ").strip()

    charsets = {
        '1': string.ascii_lowercase,
        '2': string.ascii_uppercase,
        '3': string.ascii_letters,
        '4': string.ascii_letters + string.digits,
        '5': string.ascii_letters + string.digits + string.punctuation,
        '6': string.ascii_lowercase + string.digits,
        '7': string.ascii_uppercase + string.digits,
        '8': string.hexdigits.lower(),
        '9': string.digits,
    }

    if choice in charsets:
        return charsets[choice]
    elif choice == '10':
        custom = input("Enter your custom character set: ").strip()
        if not custom:
            print("[!] Empty character set. Defaulting to letters + digits.")
            return string.ascii_letters + string.digits
        return custom
    else:
        print("[!] Invalid choice. Defaulting to letters + digits.")
        return string.ascii_letters + string.digits

def generate_passwords(charset: str, min_length: int, max_length: int) -> Generator[str, None, None]:
    """Generate passwords of increasing length from the given character set."""
    for length in range(min_length, max_length + 1):
        for pwd_tuple in product(charset, repeat=length):
            if stop_flag or found_flag:
                return
            global current_password
            current_password = ''.join(pwd_tuple)
            yield current_password

def dictionary_attack(wordlist_path: str) -> Generator[str, None, None]:
    """Generate passwords from a wordlist file."""
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if stop_flag or found_flag:
                    return
                password = line.strip()
                if password:  # Skip empty lines
                    global current_password
                    current_password = password
                    yield password
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist_path}")
        return

def try_zip(file_path: str, password: str) -> bool:
    """Attempt to extract a ZIP file with the given password."""
    try:
        with zipfile.ZipFile(file_path) as zf:
            zf.extractall(pwd=password.encode())
        return True
    except (RuntimeError, zipfile.BadZipFile):
        return False

def try_rar(file_path: str, password: str) -> bool:
    """Attempt to extract a RAR file with the given password."""
    try:
        with rarfile.RarFile(file_path) as rf:
            rf.extractall(pwd=password)
        return True
    except (rarfile.BadRarFile, rarfile.PasswordRequired, rarfile.NeedFirstVolume):
        return False

def try_7z(file_path: str, password: str) -> bool:
    """Attempt to extract a 7z file with the given password."""
    try:
        with py7zr.SevenZipFile(file_path, mode='r', password=password) as szf:
            szf.extractall()
        return True
    except (py7zr.Bad7zFile, py7zr.PasswordRequired):
        return False

def try_pdf(file_path: str, password: str) -> bool:
    """Attempt to open a PDF file with the given password."""
    try:
        with pikepdf.open(file_path, password=password) as pdf:
            # Try to access some content to verify the password
            if len(pdf.pages) > 0:
                return True
        return False
    except (pikepdf.PasswordError, pikepdf.PdfError):
        return False

def try_office(file_path: str, password: str) -> bool:
    """Attempt to decrypt an Office file with the given password."""
    try:
        with open(file_path, "rb") as f:
            office_file = msoffcrypto.OfficeFile(f)
            office_file.load_key(password=password)
            decrypted = BytesIO()
            office_file.decrypt(decrypted)
        return True
    except (msoffcrypto.exceptions.DecryptionError, msoffcrypto.exceptions.InvalidKeyError):
        return False

def try_aes(file_path: str, password: str) -> bool:
    """Attempt to decrypt an AES-encrypted file."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Try common key sizes (16, 24, 32 bytes)
        for key_size in [16, 24, 32]:
            key = password.encode().ljust(key_size, b'\0')[:key_size]
            iv = data[:16]  # Assuming IV is first 16 bytes

            try:
                cipher = AES.new(key, AES.MODE_CBC, iv)
                decrypted = unpad(cipher.decrypt(data[16:]), AES.block_size)
                # Simple check for successful decryption (look for common file headers)
                if decrypted.startswith(b'%PDF') or decrypted.startswith(b'PK') or decrypted.startswith(b'\x7fELF'):
                    return True
            except (ValueError, KeyError):
                continue
        return False
    except Exception:
        return False

def try_des(file_path: str, password: str) -> bool:
    """Attempt to decrypt a DES/DES3-encrypted file."""
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        # Try DES (8 byte key) and DES3 (16 or 24 byte key)
        for key_size in [8, 16, 24]:
            key = password.encode().ljust(key_size, b'\0')[:key_size]
            iv = data[:8]  # DES block size is 8 bytes

            try:
                if key_size == 8:
                    cipher = DES.new(key, DES.MODE_CBC, iv)
                else:
                    cipher = DES3.new(key, DES.MODE_CBC, iv)

                decrypted = unpad(cipher.decrypt(data[8:]), 8)
                # Check for common file signatures
                if decrypted.startswith(b'%PDF') or decrypted.startswith(b'PK'):
                    return True
            except (ValueError, KeyError):
                continue
        return False
    except Exception:
        return False

def try_gpg(file_path: str, password: str) -> bool:
    """Attempt to decrypt a GPG file using the gpg command-line tool."""
    try:
        # Create a temporary output file
        temp_output = file_path + ".decrypted"

        # Run gpg command
        cmd = ['gpg', '--batch', '--yes', '--passphrase', password,
               '--output', temp_output, '-d', file_path]

        result = subprocess.run(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)

        # Check if decryption was successful
        if result.returncode == 0:
            # Verify the decrypted file is not empty
            if os.path.exists(temp_output) and os.path.getsize(temp_output) > 0:
                os.remove(temp_output)  # Clean up
                return True
            os.remove(temp_output)  # Clean up if empty
        return False
    except Exception:
        return False

def try_rar5(file_path: str, password: str) -> bool:
    """Attempt to extract a RAR5 file with the given password."""
    try:
        # Use patoolib which might handle RAR5 better
        temp_dir = "temp_extract_" + str(os.getpid())
        os.makedirs(temp_dir, exist_ok=True)

        patoolib.extract_archive(file_path, outdir=temp_dir, password=password)

        # Check if extraction produced any files
        if os.listdir(temp_dir):
            # Clean up
            for f in os.listdir(temp_dir):
                os.remove(os.path.join(temp_dir, f))
            os.rmdir(temp_dir)
            return True
        return False
    except (patoolib.util.PatoolError, Exception):
        # Clean up temp dir if it exists
        temp_dir = "temp_extract_" + str(os.getpid())
        if os.path.exists(temp_dir):
            for f in os.listdir(temp_dir):
                os.remove(os.path.join(temp_dir, f))
            os.rmdir(temp_dir)
        return False

def try_zipcrypto(file_path: str, password: str) -> bool:
    """Attempt to extract a ZIP file with traditional ZIP encryption."""
    try:
        with zipfile.ZipFile(file_path) as zf:
            # Try to read the first file to verify password
            for file_info in zf.infolist():
                if not file_info.is_dir():
                    try:
                        with zf.open(file_info, pwd=password.encode()) as f:
                            f.read(16)  # Read a small chunk to verify
                        return True
                    except RuntimeError:
                        continue
        return False
    except zipfile.BadZipFile:
        return False

# Map file types to their handler functions
HANDLERS = {
    'zip': try_zip,
    'rar': try_rar,
    '7z': try_7z,
    'pdf': try_pdf,
    'docx': try_office,
    'xlsx': try_office,
    'pptx': try_office,
    'doc': try_office,
    'aes': try_aes,
    'des': try_des,
    'des3': try_des,
    'gpg': try_gpg,
    'rar5': try_rar5,
    'zipcrypto': try_zipcrypto,
}

def crack_password(file_path: str, file_type: str, password_generator: Generator[str, None, None],
                   total_passwords: int) -> Optional[str]:
    """Attempt to crack the password for the given file."""
    global found_flag, stop_flag

    start_time = time.time()
    attempts = 0
    handler = HANDLERS.get(file_type)

    if not handler:
        print(f"[!] No handler available for file type: {file_type}")
        return None

    print(f"\n[*] Starting attack on {file_path} [{file_type.upper()}]")

    with tqdm(total=total_passwords, desc="Testing passwords", unit="pwd", dynamic_ncols=True) as pbar:
        for password in password_generator:
            attempts += 1
            if stop_flag:
                break

            if handler(file_path, password):
                found_flag = True
                print(f"\n[+] Password found: {password}")
                print(f"[i] Attempts: {attempts}")
                print(f"[i] Time taken: {time.time() - start_time:.2f} seconds")
                save_stats()
                return password

            pbar.update(1)
            pbar.set_postfix({'Current': password[:20] + '...' if len(password) > 20 else password})

    if not found_flag and not stop_flag:
        print("\n[-] Password not found.")
        print(f"[i] Total attempts: {attempts}")
        print(f"[i] Time taken: {time.time() - start_time:.2f} seconds")

    save_stats()
    return None

def estimate_time(charset: str, min_len: int, max_len: int, speed: float = 1000) -> str:
    """Estimate the time required to brute-force with given parameters."""
    total = 0
    for length in range(min_len, max_len + 1):
        total += len(charset) ** length

    seconds = total / speed
    if seconds < 60:
        return f"~{seconds:.1f} seconds"
    elif seconds < 3600:
        return f"~{seconds/60:.1f} minutes"
    elif seconds < 86400:
        return f"~{seconds/3600:.1f} hours"
    else:
        return f"~{seconds/86400:.1f} days"

def get_attack_mode() -> str:
    """Prompt user to select an attack mode."""
    print("\nSelect attack mode:")
    print("1. Brute-force (all possible combinations)")
    print("2. Dictionary attack (wordlist)")
    print("3. Hybrid attack (wordlist + mutations)")

    choice = input("Enter your choice (1-3): ").strip()
    return choice

def mutate_password(password: str) -> Generator[str, None, None]:
    """Generate common mutations of a base password."""
    # Common mutations
    mutations = [
        password,
        password + '1',
        password + '123',
        password + '!',
        password.capitalize(),
        password.upper(),
        password + password,
        password + '2023',
        password + '2024',
        password + '?',
        password + '@',
        password + '#',
    ]

    for mutation in mutations:
        yield mutation

def hybrid_attack(wordlist_path: str) -> Generator[str, None, None]:
    """Combine dictionary words with common mutations."""
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if stop_flag or found_flag:
                    return
                base_word = line.strip()
                if base_word:
                    for mutation in mutate_password(base_word):
                        global current_password
                        current_password = mutation
                        yield mutation
    except FileNotFoundError:
        print(f"[!] Wordlist file not found: {wordlist_path}")
        return

def main():
    global stop_flag, found_flag

    # Set up signal handler
    signal.signal(signal.SIGINT, signal_handler)

    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Advanced Password Cracker")
    parser.add_argument("file", help="Path to the encrypted file", nargs='?')
    parser.add_argument("-t", "--type", help="Specify file type (bypass auto-detection)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist file for dictionary attack")
    parser.add_argument("-m", "--min", type=int, help="Minimum password length")
    parser.add_argument("-M", "--max", type=int, help="Maximum password length")
    parser.add_argument("-c", "--charset", help="Custom character set")
    args = parser.parse_args()

    # Get file path
    file_path = args.file if args.file else input("Enter path to password-protected file: ").strip()

    if not os.path.exists(file_path):
        print("[!] File does not exist.")
        return

    # Determine file type
    file_type = args.type if args.type else get_file_type(file_path)
    if not file_type:
        print("[!] Could not determine file type or unsupported type.")
        supported = ", ".join(sorted(SUPPORTED_TYPES.keys()))
        print(f"[i] Supported types: {supported}")
        return

    # Load previous stats
    stats = load_stats()
    if stats:
        print(f"[i] Resuming from previous session. Last tried: {stats.get('last_password_tried', 'None')}")

    # Set up password generator based on attack mode
    if args.wordlist:
        attack_mode = '2'  # Dictionary attack if wordlist is provided
    else:
        attack_mode = get_attack_mode() if not args.wordlist else '2'

    password_generator = None
    total_passwords = 0

    if attack_mode == '1':  # Brute-force
        charset = args.charset if args.charset else get_charset_from_user()
        min_length = args.min if args.min else int(input("Minimum password length: ").strip())
        max_length = args.max if args.max else int(input("Maximum password length: ").strip())

        print(f"[i] Character set size: {len(charset)}")
        print(f"[i] Estimated time: {estimate_time(charset, min_length, max_length)}")

        password_generator = generate_passwords(charset, min_length, max_length)

        # Calculate total passwords (for progress bar)
        for length in range(min_length, max_length + 1):
            total_passwords += len(charset) ** length

    elif attack_mode == '2':  # Dictionary attack
        wordlist_path = args.wordlist if args.wordlist else input("Enter path to wordlist file: ").strip()
        password_generator = dictionary_attack(wordlist_path)

        # Count lines in wordlist for progress bar
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_passwords = sum(1 for _ in f)
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {wordlist_path}")
            return

    elif attack_mode == '3':  # Hybrid attack
        wordlist_path = args.wordlist if args.wordlist else input("Enter path to wordlist file: ").strip()
        password_generator = hybrid_attack(wordlist_path)

        # Estimate total (12 mutations per word)
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                total_words = sum(1 for _ in f)
            total_passwords = total_words * 12  # Approximate
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {wordlist_path}")
            return

    else:
        print("[!] Invalid attack mode selected.")
        return

    # Start cracking
    found_password = crack_password(file_path, file_type, password_generator, total_passwords)

    if found_password:
        print("[+] Successfully cracked the password!")
        # Optionally save the result to a file
        with open("cracked_passwords.txt", "a") as f:
            f.write(f"{file_path}:{file_type}:{found_password}\n")
    elif not stop_flag:
        print("[-] Failed to crack the password with the given parameters.")

if __name__ == "__main__":
    main()
