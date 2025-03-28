package echoservice;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.util.NonceCache;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import kdcd.Ticket;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * An echo service that communicates with clients over a secure channel.
 */
public class EchoService {
    private static final String CONFIG_PATH = "test-data/service-config/config.json";
    private static int port;
    private static String serviceName;
    private static String serviceSecret;
    private static NonceCache nonceCache;

    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int GCM_IV_LENGTH = 12;   // bytes

    /**
     * Main method to start the echo service.
     * @param args
     */
    public static void main(String[] args) {
        try {
            loadConfig();

            nonceCache = new NonceCache(32, 60000);

            ServerSocket serverSocket = new ServerSocket(port);
            ExecutorService threadPool = Executors.newFixedThreadPool(10);

            System.out.println("EchoService started on port " + port);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                threadPool.execute(() -> handleClient(clientSocket));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Load the configuration from the config.json file.
     * @throws FileNotFoundException
     * @throws InvalidObjectException
     */
    private static void loadConfig() throws FileNotFoundException, InvalidObjectException {
        File configFile = new File(CONFIG_PATH);
        JSONObject config = JsonIO.readObject(configFile);

        serviceName = config.getString("service-name");
        serviceSecret = config.getString("service-secret");
        port = config.getInt("port");

        if (serviceName == null || serviceSecret == null || port <= 0) {
            throw new InvalidObjectException("Invalid configuration in config.json");
        }
    }

    /**
     * Handle a client connection.
     * @param clientSocket
     */
    private static void handleClient(Socket clientSocket) {
        try (DataInputStream input = new DataInputStream(clientSocket.getInputStream());
             DataOutputStream output = new DataOutputStream(clientSocket.getOutputStream())) {

            // Step 1: Handshake Phase
            String ticket = input.readUTF();
            String clientNonce = input.readUTF();

            // Validate ticket and extract session key
            SecretKey sessionKey = validateTicket(ticket);
            if (sessionKey == null) {
                output.writeUTF("Invalid ticket");
                return;
            }

            String serviceNonce = generateNonce();
            byte[] iv = generateIV();

            String encryptedClientNonce = encrypt(clientNonce, sessionKey, iv);

            // Send handshake response
            output.writeUTF(serviceName);
            output.writeUTF(serviceNonce);
            output.writeUTF(Base64.getEncoder().encodeToString(iv));
            output.writeUTF(encryptedClientNonce);

            // Await and validate client's handshake completion
            String clientResponse = input.readUTF();
            if (!validateClientResponse(clientResponse, serviceNonce, sessionKey, iv)) {
                output.writeUTF("Handshake failed");
                return;
            }

            // Step 2: Communication Phase
            while (true) {
                String encryptedMessage = input.readUTF();
                String decryptedMessage = decrypt(encryptedMessage, sessionKey, iv);

                String transformedMessage = decryptedMessage.toUpperCase();

                String encryptedResponse = encrypt(transformedMessage, sessionKey, iv);

                // Send the encrypted response
                output.writeUTF(encryptedResponse);
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Validates a ticket and extracts the session key.
     * @param serializedTicket The serialized ticket string.
     * @return The session key if the ticket is valid, or null if invalid.
     */
    private static SecretKey validateTicket(String serializedTicket) {
        try {
            Ticket ticket = Ticket.deserialize(serializedTicket);

            if (!ticket.getService().equals(serviceName)) {
                System.err.println("Invalid service name in ticket");
                return null;
            }

            long currentTime = System.currentTimeMillis();
            long ticketTime = ticket.getTimeStamp();
            long validityPeriod = Long.parseLong(ticket.getValidityTime());
            if (currentTime > ticketTime + validityPeriod) {
                System.err.println("Ticket has expired");
                return null;
            }

            String encryptedSessionKey = ticket.getEncryptedSessionKey();
            Cipher cipher = Cipher.getInstance("AES");
            SecretKey secretKey = new SecretKeySpec(serviceSecret.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedSessionKeyBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedSessionKey));

            return new SecretKeySpec(decryptedSessionKeyBytes, "AES");
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Generate a fresh nonce.
     * @return a fresh nonce
     */
    private static String generateNonce() {
        byte[] nonce = new byte[16];
        new java.security.SecureRandom().nextBytes(nonce);
        return Base64.getEncoder().encodeToString(nonce);
    }

    /**
     * Generate a fresh IV.
     * @return a fresh IV
     */
    private static byte[] generateIV() {
        byte[] iv = new byte[GCM_IV_LENGTH];
        new java.security.SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Encrypt data using the provided key and IV.
     * @param data
     * @param key
     * @param iv
     * @return the encrypted data
     * @throws Exception
     */
    private static String encrypt(String data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypt encrypted data using the provided key and IV.
     * @param encryptedData
     * @param key
     * @param iv
     * @return the decrypted data
     * @throws Exception
     */
    private static String decrypt(String encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(decrypted);
    }

    /**
     * Validate the client's response to the handshake.
     * @param response
     * @param expectedNonce
     * @param sessionKey
     * @param iv
     * @return true if the response is valid, false otherwise
     */
    private static boolean validateClientResponse(String response, String expectedNonce, SecretKey sessionKey, byte[] iv) {
        try {
            String decryptedResponse = decrypt(response, sessionKey, iv);
    
            return decryptedResponse.equals(expectedNonce);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Verifies a decrypted password hash.
     * @param decryptedHash The decrypted hash to verify.
     * @return True if the hash matches the expected value, false otherwise.
     */
    public boolean verifyHash(String decryptedHash) {
        try {
            // Compute the expected hash using the service secret
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] expectedHashBytes = md.digest(serviceSecret.getBytes());
            String expectedHash = Base64.getEncoder().encodeToString(expectedHashBytes);

            return decryptedHash.equals(expectedHash);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
