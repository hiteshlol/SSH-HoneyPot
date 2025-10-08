"""
SSH Honeypot for Cybersecurity Threat Analysis
A fake SSH server that logs connection attempts, credentials, and commands
for studying brute-force attacks and attacker behavior.
"""

import socket
import threading
import paramiko
import logging
import json
import sys
from datetime import datetime
from pathlib import Path

# Configuration
HOST = '0.0.0.0'
PORT = 2222
LOG_FILE = 'honeypot_logs.json'
MAX_CONNECTIONS = 50

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('honeypot.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

class SSHServerHandler(paramiko.ServerInterface):
    """Handles SSH server interactions and logs authentication attempts"""
    
    def __init__(self, client_addr):
        self.client_addr = client_addr
        self.event = threading.Event()
        
    def check_auth_password(self, username, password):
        """Log authentication attempts and always deny access"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': self.client_addr[0],
            'source_port': self.client_addr[1],
            'username': username,
            'password': password,
            'auth_method': 'password'
        }
        
        log_attempt(log_entry)
        logging.info(f"Auth attempt from {self.client_addr[0]} - User: {username}, Pass: {password}")
        
        # Always return AUTH_FAILED to keep attackers trying
        return paramiko.AUTH_FAILED
    
    def check_auth_publickey(self, username, key):
        """Log public key authentication attempts"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': self.client_addr[0],
            'source_port': self.client_addr[1],
            'username': username,
            'key_type': key.get_name(),
            'key_fingerprint': key.get_fingerprint().hex(),
            'auth_method': 'publickey'
        }
        
        log_attempt(log_entry)
        logging.info(f"Pubkey auth from {self.client_addr[0]} - User: {username}")
        return paramiko.AUTH_FAILED
    
    def get_allowed_auths(self, username):
        """Advertise supported authentication methods"""
        return 'password,publickey'
    
    def check_channel_request(self, kind, chanid):
        """Allow channel requests to keep connection alive longer"""
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_shell_request(self, channel):
        """Handle shell requests"""
        self.event.set()
        return True
    
    def check_channel_pty_request(self, channel, term, width, height, 
                                   pixelwidth, pixelheight, modes):
        """Handle PTY requests"""
        return True
    
    def check_channel_exec_request(self, channel, command):
        """Log command execution attempts"""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'source_ip': self.client_addr[0],
            'source_port': self.client_addr[1],
            'command': command.decode('utf-8', errors='ignore'),
            'type': 'exec_request'
        }
        
        log_attempt(log_entry)
        logging.info(f"Exec request from {self.client_addr[0]} - Command: {command}")
        return True

def log_attempt(entry):
    """Append log entry to JSON file"""
    try:
        logs = []
        if Path(LOG_FILE).exists():
            with open(LOG_FILE, 'r') as f:
                logs = json.load(f)
        
        logs.append(entry)
        
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        logging.error(f"Failed to write log: {e}")

def generate_host_key():
    """Generate or load RSA host key"""
    key_file = 'honeypot_rsa.key'
    
    if Path(key_file).exists():
        return paramiko.RSAKey.from_private_key_file(key_file)
    else:
        logging.info("Generating new RSA host key...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_file)
        return key

def handle_connection(client_socket, client_addr):
    """Handle individual SSH connection"""
    logging.info(f"New connection from {client_addr[0]}:{client_addr[1]}")
    
    try:
        transport = paramiko.Transport(client_socket)
        transport.local_version = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
        
        host_key = generate_host_key()
        transport.add_server_key(host_key)
        
        server = SSHServerHandler(client_addr)
        transport.start_server(server=server)
        
        # Keep connection alive for a bit
        channel = transport.accept(20)
        if channel:
            server.event.wait(10)
            channel.close()
        
    except Exception as e:
        logging.error(f"Error handling connection from {client_addr[0]}: {e}")
    finally:
        try:
            transport.close()
        except:
            pass

def start_honeypot():
    """Start the SSH honeypot server"""
    logging.info(f"Starting SSH Honeypot on {HOST}:{PORT}")
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(MAX_CONNECTIONS)
    
    logging.info("Honeypot is running. Press Ctrl+C to stop.")
    
    try:
        while True:
            client_socket, client_addr = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_connection,
                args=(client_socket, client_addr),
                daemon=True
            )
            client_thread.start()
    except KeyboardInterrupt:
        logging.info("\nShutting down honeypot...")
    finally:
        server_socket.close()

if __name__ == '__main__':
    start_honeypot()
