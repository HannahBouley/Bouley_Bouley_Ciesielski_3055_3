package signingservice;

/**
 * Extra Credit
 */

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 * A Signing Service that signs SHA-256 hashes of messages using RSA.
 */
public class signingservice {
    private static int PORT_NUMBER = 6000;
    private static PrivateKey signingKey;

    public static void main(String[] args) {
        loadSigningKey("./test-data/signing-config.json");
        
        try (ServerSocket serverSocket = new ServerSocket(PORT_NUMBER)) {
            System.out.println("Signing Server is running on port " + PORT_NUMBER);

            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(new ClientHandler(socket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Loads the signing key from a JSON configuration file.
     */
    private static void loadSigningKey(String configPath) {
        try {
            JSONType obj = JsonIO.readObject(new File(configPath));
            if (obj instanceof JSONObject) {
                JSONObject json = (JSONObject) obj;
                if (json.containsKey("signing-key")) {
                    String keyBase64 = json.getString("signing-key");
                    byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                    signingKey = keyFactory.generatePrivate(keySpec);
                } else {
                    throw new IllegalArgumentException("Missing 'signing-key' in config file");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Handles client requests for signing messages.
     */
    private static class ClientHandler implements Runnable {
        private Socket socket;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (DataInputStream in = new DataInputStream(socket.getInputStream());
                 DataOutputStream out = new DataOutputStream(socket.getOutputStream())) {

                String message = in.readUTF(); // Receive message
                String signature = signMessage(message);
                out.writeUTF(signature); // Send back Base64 signature

            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Signs a SHA-256 hash of the given message using RSA.
     */
    private static String signMessage(String message) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(message.getBytes());

        Signature rsa = Signature.getInstance("SHA256withRSA");
        rsa.initSign(signingKey);
        rsa.update(hash);
        
        return Base64.getEncoder().encodeToString(rsa.sign());
    }
}
