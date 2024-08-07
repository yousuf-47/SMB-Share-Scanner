from smb.SMBConnection import SMBConnection
from smb.base import NotConnectedError
import re
import os
import argparse

# Configuration
SEARCH_EXTENSIONS = ['.txt', '.cfg', '.sh', '.bat', '.ps1', '.ini']  # Add more extensions if needed
CREDENTIAL_PATTERNS = [
    r'(?i)password\s*[=:]\s*\S+',
    r'(?i)username\s*[=:]\s*\S+',
    r'(?i)api[_-]?key\s*[=:]\s*\S+',
    r'(?i)secret\s*[=:]\s*\S+',
    r'(?i)token\s*[=:]\s*\S+',
    r'(?i)auth(?:entication)?\s*[=:]\s*\S+'
]

def scan_smb_shares(target_ip):
    try:
        output = os.popen(f'smbclient -L {target_ip} -N').read()
        shares = re.findall(r'\t(\S+)', output)
        return shares
    except Exception as e:
        print(f"Error scanning SMB shares: {e}")
        return []

def connect_to_share(target_ip, share_name, username, password, domain):
    try:
        conn = SMBConnection(username, password, "client_machine", "remote_machine", domain, use_ntlm_v2=True)
        conn.connect(target_ip, 445)  # Port 445 is typically used for SMB
        print(f"Successfully connected to {target_ip} and share {share_name}")
        return conn
    except Exception as e:
        print(f"Error connecting to SMB share {share_name}: {e}")
        return None

def list_files(conn, share_name):
    try:
        files = conn.listPath(share_name, '/')
        return [f.filename for f in files if not f.isDirectory]
    except Exception as e:
        print(f"Error listing files in SMB share {share_name}: {e}")
        return []

def inspect_files(conn, share_name, files):
    suspicious_files = []
    for file in files:
        if any(file.endswith(ext) for ext in SEARCH_EXTENSIONS):
            try:
                with open(f'/tmp/{file}', 'wb') as file_obj:
                    conn.retrieveFile(share_name, f'/{file}', file_obj)
                with open(f'/tmp/{file}', 'r') as f:
                    content = f.read()
                    for pattern in CREDENTIAL_PATTERNS:
                        if re.search(pattern, content):
                            suspicious_files.append(file)
                            break
                os.remove(f'/tmp/{file}')
            except Exception as e:
                print(f"Error inspecting file {file}: {e}")
    return suspicious_files

def main():
    parser = argparse.ArgumentParser(description="SMB Share Scanner")
    parser.add_argument('target_ip', help="Target IP address")
    parser.add_argument('username', help="SMB username")
    parser.add_argument('password', help="SMB password")
    parser.add_argument('--domain', default='', help="SMB domain (optional)")
    args = parser.parse_args()

    # Get additional filtered shares from user
    filtered_shares = []
    custom_shares = input("Enter any shares to filter separated by commas, if not just press enter: ")
    if custom_shares:
        filtered_shares.extend(share.strip() for share in custom_shares.split(','))

    shares = scan_smb_shares(args.target_ip)
    for share in shares:
        if share in filtered_shares:
            print(f"Skipping filtered share: {share}")
            continue
        conn = connect_to_share(args.target_ip, share, args.username, args.password, args.domain)
        if conn:
            try:
                files = list_files(conn, share)
                suspicious_files = inspect_files(conn, share, files)
                if suspicious_files:
                    print(f"Suspicious files in share {share}: {suspicious_files}")
            except NotConnectedError as e:
                print(f"Connection lost to share {share}: {e}")
            finally:
                conn.close()

if __name__ == "__main__":
    main()
