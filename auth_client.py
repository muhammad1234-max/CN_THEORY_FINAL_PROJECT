#!/usr/bin/env python3
"""
AuthClient - Python TCP Client for User Authentication Server
Connects to Python auth server and provides interactive CLI
"""

import socket
import sys
import threading


class AuthClient:
    def __init__(self, host='localhost', port=9000):
        self.host = host
        self.port = port
        self.socket = None
        self.current_token = None
        self.running = True
    
    def connect(self):
        """Connect to the authentication server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            print(f"✓ Connected to auth server at {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"✗ Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server."""
        try:
            if self.current_token:
                self.send_command(f"LOGOUT {self.current_token}")
                self.read_response()
            self.send_command("QUIT")
            self.read_response()
            self.socket.close()
        except:
            pass
        print("\nDisconnected from server.")
    
    def send_command(self, command):
        """Send command to server."""
        try:
            self.socket.sendall((command + '\n').encode('utf-8'))
            print(f"[SENT] {command}")
        except Exception as e:
            print(f"Error sending: {e}")
            raise
    
    def read_response(self):
        """Read response from server."""
        try:
            data = self.socket.recv(4096).decode('utf-8').strip()
            print(f"[RECV] {data}")
            return data
        except Exception as e:
            print(f"Error reading: {e}")
            raise
    
    def register(self):
        """Register a new user."""
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        if not username or not password:
            print("Error: Username and password cannot be empty")
            return
        
        self.send_command(f"REGISTER {username} {password}")
        response = self.read_response()
        
        if response == "OK":
            print("✓ Registration successful!")
        else:
            print(f"✗ Registration failed: {response}")
    
    def login(self):
        """Login with credentials."""
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        if not username or not password:
            print("Error: Username and password cannot be empty")
            return
        
        self.send_command(f"LOGIN {username} {password}")
        response = self.read_response()
        
        if response.startswith("TOKEN:"):
            self.current_token = response[6:]
            print("✓ Login successful!")
            print("✓ Session token acquired (hidden for security)")
        else:
            print(f"✗ Login failed: {response}")
    
    def access_resource(self):
        """Access a protected resource."""
        if not self.current_token:
            print("Error: You must login first")
            return
        
        resource_id = input("Enter resource ID: ").strip()
        if not resource_id:
            print("Error: Resource ID cannot be empty")
            return
        
        self.send_command(f"ACCESS {self.current_token} {resource_id}")
        response = self.read_response()
        
        if response.startswith("DATA:"):
            print(f"✓ Access granted: {response[5:]}")
        else:
            print(f"✗ Access denied: {response}")
    
    def check_status(self):
        """Check session status."""
        if not self.current_token:
            print("Error: You must login first")
            return
        
        self.send_command(f"STATUS {self.current_token}")
        response = self.read_response()
        
        if response.startswith("ACTIVE:"):
            parts = response.split(":")
            if len(parts) >= 3:
                print(f"✓ Session active for user: {parts[1]}")
                print(f"✓ Minutes remaining: {parts[2]}")
            else:
                print("✓ Session active")
        else:
            print(f"✗ Session invalid: {response}")
            self.current_token = None
    
    def logout(self):
        """Logout current user."""
        if not self.current_token:
            print("Error: No active session")
            return
        
        self.send_command(f"LOGOUT {self.current_token}")
        response = self.read_response()
        
        if response == "OK":
            print("✓ Logout successful!")
            self.current_token = None
        else:
            print(f"✗ Logout failed: {response}")
    
    def print_help(self):
        """Print help menu."""
        print("\n" + "="*50)
        print("           AVAILABLE COMMANDS")
        print("="*50)
        print("  1. register  - Register a new user")
        print("  2. login     - Login with credentials")
        print("  3. access    - Access a protected resource")
        print("  4. status    - Check session status")
        print("  5. logout    - Logout current session")
        print("  6. help      - Show this help menu")
        print("  7. quit      - Exit the client")
        print("="*50 + "\n")
    
    def run(self):
        """Main interactive loop."""
        print("\n" + "="*50)
        print("    USER AUTHENTICATION CLIENT (Python)")
        print("="*50)
        print(f"Server: {self.host}:{self.port}")
        print("="*50)
        self.print_help()
        
        while self.running:
            try:
                command = input("auth> ").strip().lower()
                
                if command in ['1', 'register', 'reg']:
                    self.register()
                elif command in ['2', 'login', 'li']:
                    self.login()
                elif command in ['3', 'access', 'acc']:
                    self.access_resource()
                elif command in ['4', 'status', 'st']:
                    self.check_status()
                elif command in ['5', 'logout', 'lo']:
                    self.logout()
                elif command in ['6', 'help', 'h', '?']:
                    self.print_help()
                elif command in ['7', 'quit', 'exit', 'q']:
                    self.running = False
                elif command == '':
                    continue
                else:
                    print(f"Unknown command: {command}")
                    print("Type 'help' for available commands")
            
            except KeyboardInterrupt:
                print("\nUse 'quit' to exit properly")
            except Exception as e:
                print(f"\nConnection error: {e}")
                print("Attempting to reconnect...")
                if not self.reconnect():
                    print("Failed to reconnect. Exiting...")
                    self.running = False
        
        self.disconnect()
        print("Goodbye!")
    
    def reconnect(self):
        """Attempt to reconnect to server."""
        try:
            self.socket.close()
        except:
            pass
        return self.connect()


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Authentication Client')
    parser.add_argument('--host', default='localhost', help='Server host (default: localhost)')
    parser.add_argument('--port', type=int, default=9000, help='Server port (default: 9000)')
    args = parser.parse_args()
    
    client = AuthClient(args.host, args.port)
    if client.connect():
        client.run()
    else:
        print("\nCould not connect to server. Please check:")
        print("1. Server is running on {}:{}".format(args.host, args.port))
        print("2. Firewall settings allow the connection")
        print("3. Server host and port are correct")
        sys.exit(1)


if __name__ == "__main__":
    main()
