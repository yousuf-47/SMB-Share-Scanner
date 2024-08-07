
# SMB Share Scanner Tool

The SMB Share Scanner Tool is a cybersecurity tool designed to scan and inspect SMB shares for potentially sensitive files. It connects to SMB shares, lists the files, and searches for specific patterns that may indicate the presence of credentials or other sensitive information.

**Disclaimer: This tool is intended for educational purposes only. Use it responsibly and only on networks and systems you have permission to test.**

## Features

- **SMB Share Scanning**: Scans for available SMB shares on a target IP.
-  **Inspection**: Lists and inspects files within SMB shares for sensitive information based on configurable patterns and file extensions.
- **Custom Filtering**: Allows users to skip specific SMB shares during the scanning process.
- **User-Friendly Interface**: Command-line interface for easy usage and integration.


## Installation

To get started with the SMB Share Scanner Tool, follow these steps:

- **Clone the repository**:

  ```bash
  git clone https://github.com/yousuf-47/SMB-Share-Scanner.git
  cd SMB-Share-Scanner
  ```

- **Install the required packages**:

  ```bash
  pip Install -r requirements.txt
  ```

- **Run the application**:

  ```bash
  python smb_scanner.py --help
  ```

  


    
## Usage

- **Basic Usage**:

  ```bash
  python smb_scanner.py <target_ip> <username> <password>
  ```

- **With Optional Domain**:

  ```bash
  python smb_scanner.py <target_ip> <username> <password> --domain <domain>
  ```

- **Filtering Specific Shares**:
  When prompted, enter the names of shares to filter, separated by commas.

## Example

```bash
python smb_scanner.py 192.168.1.10 myusername mypassword
```

When prompted for shares to filter, enter the share names separated by commas, or press Enter to skip filtering.

## Configuration

The tool is configured to search for specific file extensions and credential patterns:

- **Search Extensions**: **'.txt'**, **'.cfg'**, **'.sh'**, **'.bat'**, **'.ps1'**, **'.ini'**
- **Credential Patterns**:
  - 'password\s*[=:]\s*\S+'
  - 'username\s*[=:]\s*\S+'
  - 'api[_-]?key\s*[=:]\s*\S+'
  - 'secret\s*[=:]\s*\S+'
  - 'token\s*[=:]\s*\S+'
  - 'auth(?:entication)?\s*[=:]\s*\S+'
## License

This project is licensed under the [MIT](https://choosealicense.com/licenses/mit/) License


## Acknowledgements

 - Thanks to the authors of the **pysmb** library for providing the SMB protocol support.
 - Inspiration from various cybersecurity tools and SMB scanning techniques.

