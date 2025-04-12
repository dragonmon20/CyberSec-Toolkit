import hashlib
import os


def calculate_file_hash(file_path):
    """Calculate the SHA256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None

def scan_directory(directory_path, output_file):
    """Scan all files in a directory and save their hashes to a file."""
    try:
        with open(output_file, "w") as out_file:
            for root, _, files in os.walk(directory_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    print(f"Processing file: {file_path}")
                    file_hash = calculate_file_hash(file_path)
                    if file_hash:
                        out_file.write(f"{file_path},{file_hash}\n")
                        print(f"SHA256: {file_hash}")
                    print("-" * 50)
        print(f"Hashes saved to {output_file}")
    except Exception as e:
        print(f"Error writing to output file: {e}")

if __name__ == "__main__":
    directory_to_scan = input("Enter the directory path to scan: ").strip()
    output_file = input("Enter the output file path (e.g., hashes.csv): ").strip()
    if os.path.isdir(directory_to_scan):
        scan_directory(directory_to_scan, output_file)
    else:
        print("Invalid directory path.")
