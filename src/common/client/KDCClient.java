package client;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;




public class KDCClient {

    /*
      * For reference:
      * 
      * java -jar dist/kdcclient.jar -h ./test-data/hosts.json -u alice -s echoservice
      */

    // Set via command line.
    private static String configFile = null;  // now using -c for config/hosts file
    private static String userName = null;
    private static String service = null;
    private static String password = null;

    // AES/GCM parameters.
    private static final int GCM_TAG_LENGTH = 128; // bits
    private static final int GCM_IV_LENGTH = 12;   // bytes

    // Simple inner class to hold host entry data.
    private static class HostEntry {
        String hostName;
        String address;
        int port;
    }

    public static void main(String[] args) throws Exception {

        // Add bc provider
        Security.addProvider(new BouncyCastleProvider());

        // Parse command-line inputs.
        if (args.length < 1) {
            printUsage();
            System.exit(1);
        } else {
            handleCommandLineInputs(args);
        }

        // Create a scanner for prompting.
        Scanner scanner = new Scanner(System.in);

        // Prompt for missing parameters.
        if (configFile == null) {
            System.out.print("Enter configuration file (hosts file) path: ");
            System.out.flush();
            configFile = scanner.nextLine();
        }
        if (userName == null) {
            System.out.print("Enter user name: ");
            System.out.flush();
            userName = scanner.nextLine();
        }
        if (service == null) {
            System.out.print("Enter service name: ");
            System.out.flush();
            service = scanner.nextLine();
        }
        
        // Prompt for password.
        Console console = System.console();
        char[] passwordChars = null;
        if (console != null) {
            System.out.print("Enter password: ");
            System.out.flush();
            passwordChars = console.readPassword();
        } else {
            System.out.print("Enter password: ");
            System.out.flush();
            passwordChars = scanner.nextLine().toCharArray();
        }
        password = new String(passwordChars);
        System.out.println("Password received.");

        // Read configuration file.
        Map<String, HostEntry> hostsMap = new HashMap<>();
        try {
            hostsMap = readHostsFile(configFile);
            System.out.println("Configuration file read successfully.");
        } catch (Exception e) {
            System.err.println("Error reading config file: " + e.getMessage());
            System.exit(1);
        }

        // Get KDC host 
        HostEntry kdcHost = hostsMap.get("kdcd");
        if (kdcHost == null) {
            System.err.println("Config file does not contain a 'kdcd' entry.");
            System.exit(1);
        }
        // Get Service host based on the provided service name.
        HostEntry serviceHost = hostsMap.get(service);
        if (serviceHost == null) {
            System.err.println("Config file does not contain an entry for service: " + service);
            System.exit(1);
        }

        // CHAP Authentication and Session Key Exchange with KDC 
        SecretKey sessionKey = null;
        System.out.println("Attempting to connect to KDC at " + kdcHost.address + ":" + kdcHost.port);
        try (Socket kdcSocket = new Socket(kdcHost.address, kdcHost.port)) {
            System.out.println("Connected to KDC.");
            DataInputStream recv = new DataInputStream(kdcSocket.getInputStream());
            DataOutputStream send = new DataOutputStream(kdcSocket.getOutputStream());

            // Send username and cleartext password.
            System.out.println("Sending username and password to KDC...");
            send.writeUTF(userName);
            send.writeUTF(password);

            // Receive challenge (nonce) from KDC (Base64 encoded).
            String challenge = recv.readUTF();
            System.out.println("Received challenge from KDC: " + challenge);

            // Compute response: SHA-256(challenge + password)
            String responseHash = hash(challenge + password);
            System.out.println("Computed response hash.");

            // Send computed hash back to KDC.
            send.writeUTF(responseHash);
            System.out.println("Sent response hash to KDC.");

            // Response to user. Either valid or not.
            boolean valitated = recv.readBoolean();
            
            if (valitated){
                System.out.println("ACCESS GRANTED");

                

            } else {
                System.out.println("ACCESS DENIED");
                System.exit(1); // Kick from server
        }
        
            // Ticket request from client
            send.writeUTF(service); // Send the service that the client is rquesting
            String ticketData = recv.readUTF(); // The resulting ticket data
            System.out.println(ticketData);

            Ticket ticket = Ticket.deserialize(ticketData);
            byte[] iv = ticket.getIv();
            System.out.println(java.util.Arrays.toString(iv));

            
            // Derive root key using SCRYPT with username as salt.
            SecretKey rootKey = deriveRootKey(password, userName);

            // Receive encrypted session key from the KDC.
            String encryptedSessionKey = recv.readUTF();

            sessionKey = decryptSessionKey(encryptedSessionKey, iv, rootKey);
            System.out.println("Decrypted Session Key (Base64): " +
                   Base64.getEncoder().encodeToString(sessionKey.getEncoded()));

            // Clear sensitive data.
            java.util.Arrays.fill(passwordChars, '\0');
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }

        // Service Communication Protocol 
        System.out.println("Attempting to connect to service at " + serviceHost.address + ":" + serviceHost.port);
        try (Socket serviceSocket = new Socket(serviceHost.address, serviceHost.port)) {
            System.out.println("Connected to service.");
            DataInputStream recvService = new DataInputStream(serviceSocket.getInputStream());
            DataOutputStream sendService = new DataOutputStream(serviceSocket.getOutputStream());

            // Send a handshake
            System.out.println("Performing service handshake...");
            sendService.writeUTF("HANDSHAKE");
            String handshakeResponse = recvService.readUTF();
            if (!"HANDSHAKE_ACK".equals(handshakeResponse)) {
                System.out.println("Service handshake failed.");
                System.exit(1);
            }
            System.out.println("Service handshake successful.");

            // Communication Phase: allow the user to type messages to be echoed back.
            System.out.println("Enter messages to send to the service (type 'exit' to quit):");
            while (true) {
                System.out.print("> ");
                String msg = scanner.nextLine();
                if ("exit".equalsIgnoreCase(msg.trim())) {
                    break;
                }
                sendService.writeUTF(msg);
                String echo = recvService.readUTF();
                System.out.println("Service responded: " + echo);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        scanner.close();
        System.out.println("Client terminated.");
    }



    /**
     * Reads the configuration file (hosts file) as text and manually parses the content
     * to create a map from host-name to HostEntry. 
     */
    private static Map<String, HostEntry> readHostsFile(String fileName) throws Exception {
        Map<String, HostEntry> hosts = new HashMap<>();
        String content = new String(Files.readAllBytes(Paths.get(fileName)), StandardCharsets.UTF_8);
        // Remove newlines and extra spaces.
        content = content.replaceAll("\\s+", "");
        // Find the hosts array between "hosts":[ and the closing ]
        int hostsStart = content.indexOf("\"hosts\":[");
        if (hostsStart == -1) {
            throw new Exception("Invalid config file format: missing \"hosts\" array.");
        }
        hostsStart += "\"hosts\":[".length();
        int hostsEnd = content.indexOf("]", hostsStart);
        if (hostsEnd == -1) {
            throw new Exception("Invalid config file format: missing closing bracket for hosts array.");
        }
        String hostsArray = content.substring(hostsStart, hostsEnd);
        // Split individual host entries. Assumes entries are separated by "},{"
        String[] entries = hostsArray.split("\\},\\{");
        for (String entryStr : entries) {
            // Clean up braces if present.
            entryStr = entryStr.replaceAll("^\\{", "").replaceAll("\\}$", "");
            HostEntry entry = new HostEntry();
            // Split key-value pairs by comma.
            String[] pairs = entryStr.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":");
                if (kv.length < 2)
                    continue;
                String key = kv[0].replaceAll("\"", "");
                String value = kv[1].replaceAll("\"", "");
                if ("host-name".equals(key)) {
                    entry.hostName = value;
                } else if ("address".equals(key)) {
                    entry.address = value;
                } else if ("port".equals(key)) {
                    entry.port = Integer.parseInt(value);
                }
            }
            if (entry.hostName != null) {
                hosts.put(entry.hostName, entry);
            }
        }
        return hosts;
    }

    /**
     * Derives the root key from the password using SCRYPT with the username as salt.
     * The salt is the Base64 encoding of the username's UTF-8 bytes.
     */
    private static SecretKey deriveRootKey(String password, String username) throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] salt = Base64.getEncoder().encode(username.getBytes(StandardCharsets.UTF_8));
        // Parameters: N=2048, r=8, p=1, key length=128 bits.
        ScryptKeySpec spec = new ScryptKeySpec(password.toCharArray(), salt, 2048, 8, 1, 128);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT");
        return skf.generateSecret(spec);
    }

    /**
     * Decrypts an encrypted session key using AES/GCM/NoPadding.
     * The input format is assumed to be "iv:ciphertext" (both Base64 encoded).
     */
    private static SecretKey decryptSessionKey(String encryptedData, byte[] iv, SecretKey rootKey) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(rootKey.getEncoded(), "AES"), gcmSpec);
    
        // Assume encryptedData is just the Base64 encoded ciphertext
        byte[] cipherBytes = Base64.getDecoder().decode(encryptedData);
    
        // Decrypt the session key using the cipher
        byte[] sessionKeyBytes = cipher.doFinal(cipherBytes);
    
        return new SecretKeySpec(sessionKeyBytes, "AES");
    }
    
    
    

    /**
     * Computes a SHA-256 hash of the input and returns the result as a Base64 encoded string.
     */
    private static String hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    /**
     * Handles command-line inputs for config file (-c), user (-u), and service (-s).
     */
    private static void handleCommandLineInputs(String[] args) {
        OptionParser optParser = new OptionParser(args);
        Tuple<Character, String> currOpt;
        // Added 'c' for config file.
        optParser.setOptString("c:h:u:s:");

        LongOption[] longOpts = new LongOption[4];
        longOpts[0] = new LongOption("config", true, 'c');
        longOpts[1] = new LongOption("hostsFile", true, 'h');
        longOpts[2] = new LongOption("userName", true, 'u');
        longOpts[3] = new LongOption("service", true, 's');
        optParser.setLongOpts(longOpts);

        while (optParser.getOptIdx() != args.length) {
            currOpt = optParser.getLongOpt(false);
            switch (currOpt.getFirst()) {
                case 'c': // Config file.
                    configFile = currOpt.getSecond();
                    break;
                case 'h': // Alternative way to specify config file.
                    configFile = currOpt.getSecond();
                    break;
                case 'u': // User name.
                    userName = currOpt.getSecond();
                    break;
                case 's': // Service name.
                    service = currOpt.getSecond();
                    break;
                case '?':
                default:
                    break;
            }
        }
    }

    private static void printUsage() {
        System.out.println("Usage:");
        System.out.println("    java -jar dist/kdcclient.jar --config <configFile> --user <user> --service <service>");
        System.out.println("    java -jar dist/kdcclient.jar --user <user> --service <service>");
        System.out.println("Options:");
        System.out.println("    -c, --config   Set the configuration file (hosts file).");
        System.out.println("    -h, --hosts    Set the configuration file (hosts file).");
        System.out.println("    -u, --user     The user name.");
        System.out.println("    -s, --service  The name of the service");
    }
}

