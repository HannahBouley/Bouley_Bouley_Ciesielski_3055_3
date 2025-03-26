package echoservice;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import merrimackutil.util.NonceCache;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.InvalidObjectException;

public class EchoService {
    private static final String CONFIG_PATH = "config.json";
    private static int port;
    private static String serviceName;
    private static String serviceSecret;
    private static NonceCache nonceCache;

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

    public boolean verifyHash(String decryptedHash) {
        // Fill in for now, please use same method name if not, update in PasswordVerify
        throw new UnsupportedOperationException("Unimplemented method 'verifyHash'");
    }

}
