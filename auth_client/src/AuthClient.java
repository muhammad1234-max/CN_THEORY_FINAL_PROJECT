import java.io.*;
import java.net.*;
import java.util.Scanner;

/**
 * AuthClient - TCP Client for User Authentication Server
 * Connects to Python auth server and provides interactive CLI
 */
public class AuthClient {
    private Socket socket;
    private BufferedReader reader;
    private PrintWriter writer;
    private Scanner scanner;
    private String currentToken;
    private String serverHost;
    private int serverPort;
    private boolean running;
    
    public AuthClient(String host, int port) {
        this.serverHost = host;
        this.serverPort = port;
        this.scanner = new Scanner(System.in);
        this.currentToken = null;
        this.running = true;
    }
    
    /**
     * Connect to the authentication server
     */
    public boolean connect() {
        try {
            socket = new Socket(serverHost, serverPort);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new PrintWriter(socket.getOutputStream(), true);
            System.out.println("Connected to auth server at " + serverHost + ":" + serverPort);
            return true;
        } catch (IOException e) {
            System.err.println("Failed to connect: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * Disconnect from server
     */
    public void disconnect() {
        try {
            if (socket != null && !socket.isClosed()) {
                if (currentToken != null) {
                    sendCommand("LOGOUT " + currentToken);
                    readResponse();
                }
                sendCommand("QUIT");
                readResponse();
                socket.close();
            }
        } catch (IOException e) {
            System.err.println("Error during disconnect: " + e.getMessage());
        }
    }
    
    /**
     * Send command to server
     */
    private void sendCommand(String command) {
        writer.println(command);
        System.out.println("[SENT] " + command);
    }
    
    /**
     * Read response from server
     */
    private String readResponse() throws IOException {
        String response = reader.readLine();
        System.out.println("[RECV] " + response);
        return response;
    }
    
    /**
     * Register a new user
     */
    private void register() throws IOException {
        System.out.print("Enter username: ");
        String username = scanner.nextLine().trim();
        System.out.print("Enter password: ");
        String password = scanner.nextLine().trim();
        
        if (username.isEmpty() || password.isEmpty()) {
            System.out.println("Error: Username and password cannot be empty");
            return;
        }
        
        sendCommand("REGISTER " + username + " " + password);
        String response = readResponse();
        
        if (response.equals("OK")) {
            System.out.println("Registration successful!");
        } else {
            System.out.println("Registration failed: " + response);
        }
    }
    
    /**
     * Login with credentials
     */
    private void login() throws IOException {
        System.out.print("Enter username: ");
        String username = scanner.nextLine().trim();
        System.out.print("Enter password: ");
        String password = scanner.nextLine().trim();
        
        if (username.isEmpty() || password.isEmpty()) {
            System.out.println("Error: Username and password cannot be empty");
            return;
        }
        
        sendCommand("LOGIN " + username + " " + password);
        String response = readResponse();
        
        if (response.startsWith("TOKEN:")) {
            currentToken = response.substring(6);
            System.out.println("Login successful!");
            System.out.println("Session token acquired (hidden for security)");
        } else {
            System.out.println("Login failed: " + response);
        }
    }
    
    /**
     * Access a protected resource
     */
    private void accessResource() throws IOException {
        if (currentToken == null) {
            System.out.println("Error: You must login first");
            return;
        }
        
        System.out.print("Enter resource ID: ");
        String resourceId = scanner.nextLine().trim();
        
        if (resourceId.isEmpty()) {
            System.out.println("Error: Resource ID cannot be empty");
            return;
        }
        
        sendCommand("ACCESS " + currentToken + " " + resourceId);
        String response = readResponse();
        
        if (response.startsWith("DATA:")) {
            System.out.println("Access granted: " + response.substring(5));
        } else {
            System.out.println("Access denied: " + response);
        }
    }
    
    /**
     * Check session status
     */
    private void checkStatus() throws IOException {
        if (currentToken == null) {
            System.out.println("Error: You must login first");
            return;
        }
        
        sendCommand("STATUS " + currentToken);
        String response = readResponse();
        
        if (response.startsWith("ACTIVE:")) {
            String[] parts = response.split(":");
            if (parts.length >= 3) {
                System.out.println("Session active for user: " + parts[1]);
                System.out.println("Minutes remaining: " + parts[2]);
            } else {
                System.out.println("Session active");
            }
        } else {
            System.out.println("Session invalid: " + response);
            currentToken = null;
        }
    }
    
    /**
     * Logout current user
     */
    private void logout() throws IOException {
        if (currentToken == null) {
            System.out.println("Error: No active session");
            return;
        }
        
        sendCommand("LOGOUT " + currentToken);
        String response = readResponse();
        
        if (response.equals("OK")) {
            System.out.println("Logout successful!");
            currentToken = null;
        } else {
            System.out.println("Logout failed: " + response);
        }
    }
    
    /**
     * Print help menu
     */
    private void printHelp() {
        System.out.println("\n=== Available Commands ===");
        System.out.println("1. register - Register a new user");
        System.out.println("2. login    - Login with credentials");
        System.out.println("3. access   - Access a protected resource");
        System.out.println("4. status   - Check session status");
        System.out.println("5. logout   - Logout current session");
        System.out.println("6. help     - Show this help menu");
        System.out.println("7. quit     - Exit the client");
        System.out.println("========================\n");
    }
    
    /**
     * Main interactive loop
     */
    public void run() {
        System.out.println("\n=== User Authentication Client ===");
        System.out.println("Connected to server: " + serverHost + ":" + serverPort);
        printHelp();
        
        while (running) {
            try {
                System.out.print("\nauth> ");
                String input = scanner.nextLine().trim().toLowerCase();
                
                switch (input) {
                    case "1":
                    case "register":
                        register();
                        break;
                    case "2":
                    case "login":
                        login();
                        break;
                    case "3":
                    case "access":
                        accessResource();
                        break;
                    case "4":
                    case "status":
                        checkStatus();
                        break;
                    case "5":
                    case "logout":
                        logout();
                        break;
                    case "6":
                    case "help":
                        printHelp();
                        break;
                    case "7":
                    case "quit":
                    case "exit":
                        running = false;
                        break;
                    default:
                        System.out.println("Unknown command: " + input);
                        System.out.println("Type 'help' for available commands");
                        break;
                }
            } catch (IOException e) {
                System.err.println("Connection error: " + e.getMessage());
                System.out.println("Attempting to reconnect...");
                if (!reconnect()) {
                    System.out.println("Failed to reconnect. Exiting...");
                    running = false;
                }
            }
        }
        
        disconnect();
        System.out.println("Goodbye!");
    }
    
    /**
     * Attempt to reconnect to server
     */
    private boolean reconnect() {
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
            return connect();
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * Main entry point
     */
    public static void main(String[] args) {
        String host = "localhost";
        int port = 9000;
        
        // Parse command line arguments
        if (args.length >= 1) {
            host = args[0];
        }
        if (args.length >= 2) {
            try {
                port = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("Invalid port number: " + args[1]);
                System.exit(1);
            }
        }
        
        AuthClient client = new AuthClient(host, port);
        if (client.connect()) {
            client.run();
        } else {
            System.err.println("Could not connect to server. Please check:");
            System.err.println("1. Server is running on " + host + ":" + port);
            System.err.println("2. Firewall settings allow the connection");
            System.err.println("3. Server host and port are correct");
            System.exit(1);
        }
    }
}
