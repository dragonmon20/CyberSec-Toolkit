# Anonymous Tools - `anonymous.py`

⚠ **Warning**: This tool is intended for educational and ethical use only. Unauthorized use is strictly prohibited.

## Overview

`anonymous.py` is a Python-based tool designed to demonstrate techniques for anonymizing network activity. It provides users with the ability to route their traffic through proxies or VPNs, mask their IP address, and test the effectiveness of anonymization techniques.

### Features
- **Proxy Support**: Route traffic through HTTP/SOCKS proxies.
- **IP Masking**: Test IP address masking techniques.
- **Customizable Settings**: Configure proxy servers, ports, and other parameters.
- **Educational Purpose**: Learn about anonymization techniques and their limitations.

---

## Installation

To use `anonymous.py`, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/Amr-Khaled-Ahmed/Hack-Tools.git
   cd Hack-Tools/anonymous-tools
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

---

## Usage

Run the script using Python:

```bash
python anonymous.py --proxy <proxy_url> --port <proxy_port>
```

### Example:
```bash
python anonymous.py --proxy http://127.0.0.1 --port 8080
```

### Command-Line Arguments:
- `--proxy`: Specify the proxy server URL (e.g., `http://127.0.0.1`).
- `--port`: Specify the proxy server port (e.g., `8080`).
- `--test`: Test the anonymization by checking your public IP address.

---

## Prerequisites

- Python 3.x installed on your system.
- Basic understanding of networking and anonymization concepts.

---

## Legal Disclaimer

❗ **Important**:
- This tool is provided for **educational and ethical use only**.
- Unauthorized use against any systems without explicit permission is **illegal** and may result in severe penalties under applicable laws.
- The maintainer assumes **no liability** for any misuse of this tool.
- Users are solely responsible for ensuring their actions comply with all local, state, and federal laws.

---

## Contribution

Contributions to this project are welcome. If you have ideas for improvements or additional features, feel free to open an issue or submit a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](../../LICENSE) file for details.
