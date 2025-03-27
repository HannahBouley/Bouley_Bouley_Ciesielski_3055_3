package echoservice;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import merrimackutil.util.NonceCache;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.InvalidObjectException;
import java.net.Socket;
import java.security.SecureRandom;
import java.util.Base64;

public class EchoService {
    private static final String CONFIG_PATH = "config.json";
    private static int port;
    private static String serviceName;
    private static String serviceSecret;
    private static NonceCache nonceCache;

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int IV_SIZE = 16;

    public static void main(String[] args) {
        try {
            loadConfig();
            nonceCache = new NonceCache(32, 60000); // 32-byte nonces, 60s expiration
            System.out.println("EchoService initialized on port " + port);
        } catch (Exception e) {
            System.err.println("Failed to initialize EchoService: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void loadConfig() throws Exception {
        File configFile = new File(CONFIG_PATH);
        if (!configFile.exists()) {
            throw new FileNotFoundException("Config file not found: " + CONFIG_PATH);
        }
        
        JSONType configData = JsonIO.readObject(configFile);
        if (!(configData instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSON object in config file");
        }
        
        JSONObject config = (JSONObject) configData;
        
        if (!config.containsKey("port") || !config.containsKey("service-name") || !config.containsKey("service-secret")) {
            throw new InvalidObjectException("Config file missing required fields");
        }
        
        port = config.getInt("port");
        serviceName = config.getString("service-name");
        serviceSecret = config.getString("service-secret");
    }

    public void handleClient(Socket clientSocket) {
        try (DataInputStream in = new DataInputStream(clientSocket.getInputStream());
             DataOutputStream out = new DataOutputStream(clientSocket.getOutputStream())) {
            
            // Step 1: Receive Client Hello (nonce and ticket)
            String clientHello = in.readUTF();
            System.out.println("Received Client Hello: " + clientHello);
            
            // Step 2: Validate ticket (Placeholder - actual validation needed)
            if (!validateTicket(clientHello)) {
                out.writeUTF("Invalid Ticket");
                return;
            }
            
            // Step 3: Generate fresh nonce and IV
            String freshNonce = generateNonce();
            byte[] iv = new byte[IV_SIZE];
            secureRandom.nextBytes(iv);
            
            // Encrypt client's nonce (Placeholder - actual encryption needed)
            String encryptedNonce = encryptNonce(clientHello, iv);
            
            // Step 4: Send handshake response
            out.writeUTF(freshNonce + "," + Base64.getEncoder().encodeToString(iv) + "," + encryptedNonce);
            
            // Step 5: Await and validate client's handshake completion
            String clientResponse = in.readUTF();
            if (!validateClientResponse(clientResponse)) {
                out.writeUTF("Handshake Failed");
                return;
            }
            
            out.writeUTF("Handshake Successful");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private boolean validateTicket(String ticket) {
        // Placeholder for actual ticket validation logic
        return ticket.contains("valid");
    }

    private String generateNonce() {
        byte[] nonce = new byte[16];
        secureRandom.nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }
    
    private String encryptNonce(String nonce, byte[] iv) throws Exception {
        // Placeholder for encryption logic
        return Base64.getEncoder().encodeToString(nonce.getBytes());
    }

    private boolean validateClientResponse(String response) {
        // Placeholder for actual client handshake validation logic
        return response.contains("valid");
    }
    
    public boolean verifyHash(String decryptedHash) {
        // Fill in for now, please use same method name if not, update in PasswordVerify
        throw new UnsupportedOperationException("Unimplemented method 'verifyHash'");
    }

}
