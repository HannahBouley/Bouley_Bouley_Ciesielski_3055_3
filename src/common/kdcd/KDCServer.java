package kdcd;

import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jcajce.spec.ScryptKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.json.JSONSerializable;
import merrimackutil.json.JsonIO;
import merrimackutil.json.parser.JSONParser;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;
import merrimackutil.util.NonceCache;
import merrimackutil.util.Tuple;

import java.io.*;
import java.lang.reflect.InaccessibleObjectException;
import java.net.*;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.*;


/**
 * The server in which the client will connect to
 */
public class KDCServer{
    /**
     *  For reference: 
     * 
     *  Config and run: java -jar dist/kdcd.jar -c ./test-data/kdc-config/config.json
     *  Display help: java -jar dist/kdcd.jar -h
     * */ 

    private static final int POOL_SIZE = 10; // MAX NUM OF CONNECTIONS
    
    private static int PORT_NUMBER = 5000; // PORT NUMBER THE SERVER IS RUNS ON
    private static String secretsFile = "./test-data/kdc-config/secrets.json"; // FILE THAT HOLDS SECRETS
    private static String validityPeriod = "60000"; // THE PERIOD THAT THE TICKET IS VALID FOR
    public static NonceCache nonceCache;

    // Entry point for the server
    public static void main(String[] args) {
        // Add bc provider
        Security.addProvider(new BouncyCastleProvider());

        // Read the commands on the command line
        handleCommandLineInput(args);

        // Create a new thread pool to handle server-client connections
        ExecutorService executor = Executors.newFixedThreadPool(POOL_SIZE);

        // Create a server socket with a port number
        try(ServerSocket serverSocket = new ServerSocket(PORT_NUMBER)){
            
            System.out.println("Server is running");

            // Always keep the server running to accept incoming request from clients
            while (true) {
                Socket socket = serverSocket.accept(); // Accept a new client to the server

                System.out.println("connection recieved from client " + socket.getInetAddress());
                executor.submit(new HandleClientConnections(socket));

                            }
                        } catch (IOException e){
                            e.printStackTrace();
                        } finally {
                            executor.shutdown();
                        }
                    }


    /**
     * Handles inputs from the command line
     */
    private static void handleCommandLineInput(String[] args){
        
        OptionParser optParser = new OptionParser(args);
        Tuple<Character, String> currOpt;

        // Set up the option parser
        optParser.setOptString("hc:"); // Only need two commands

        LongOption[] longOpts = new LongOption[2];

        longOpts[0] = new LongOption("help", false, 'h'); // Help command
        longOpts[1] = new LongOption("config", true, 'c'); // Congigure a file

        optParser.setLongOpts(longOpts);

        while(optParser.getOptIdx() != args.length){
            currOpt = optParser.getLongOpt(false);

            switch (currOpt.getFirst()) {
                case 'h': // Simply display the help menu
                    System.out.println("usage:");
                    System.out.println("    kdcd");
                    System.out.println("    kdcd --config <configfile>");
                    System.out.println("    kdcd --help");
                    System.out.println("options:");
                    System.out.println("    -c, --config Set the config file.");
                    System.out.println("    -h, --help Display the help.");

                    // Exit since only the menu was displayed
                    System.exit(1);
                    break;

                case 'c': // Configure w/ file, start the server
                    System.out.println("Configuring file...");

                    try {
                        
                        // Configure using the file path
                        config(JsonIO.readObject(new File(currOpt.getSecond())));

                    } catch (Exception e) {
                        
                        e.printStackTrace();
                    }

                    break;


                case '?': // Finished with commands
                    System.exit(1);
                    break;
            
                default:
                    System.exit(1);
                    break;
            }
        }
        
    }

    /**
     * Configure the server by reading a JSON file
     */
    private static void config(JSONType obj) throws Exception{

        JSONObject tmp;

        if (obj instanceof JSONObject){
            tmp = (JSONObject) obj;

            if (tmp.containsKey("secrets-file")){
                secretsFile = tmp.getString("secrets-file");
            } else {
                throw new InvalidObjectException("Expected field: secrets-file");   
            }
            if (tmp.containsKey("port")){
                PORT_NUMBER = tmp.getInt("port");
            } else {
                throw new InvalidObjectException("Expected field: port");
            }
            if (tmp.containsKey("validity-period")){
                validityPeriod = tmp.getString("validity-period");
            } else {
                throw new InvalidObjectException("Expected field: validity-period");
            }
            System.out.println("Server configured!");
        } 
    }
    
}

/**
 * Handles client connections to the server
 */
class HandleClientConnections implements Runnable{
    
    private static final int NONCE_SIZE = 32; // THE SIZE OF THE NONCE FOR THE CACHE
    private Socket socket; // The socket that represents the connection
    private static String userName;
    private static String password;
    private String salt;
    private String service;
    private static byte[] IV;
    private static SecretKey rootKey;
    private static String sessionKey;

    // Create a new nonce cache
    private static NonceCache nonceCache = new NonceCache(NONCE_SIZE, 60000);

    HandleClientConnections(Socket socket){
        this.socket = socket;
        this.salt = null;
    }

    /**
     * Generates a random challenge that is sent to the specified user
     * @param userName
     * @throws Exception
     */
    private static String generateChallenge(String userName) throws Exception{

        // Create a new nonce
        byte[] nonce = nonceCache.getNonce(); // This also adds it to the cache so we don't have to add it again

        // Determine if the username is in the secret store
        JSONObject obj = JsonIO.readObject(new File("./test-data/kdc-config/secrets.json"));

        JSONObject tmp;
        JSONArray tmpArry;

        if (obj instanceof JSONObject){
            tmp = (JSONObject) obj;
            
            if (tmp.containsKey("secrets")){
                
                if (tmp.getArray("secrets") instanceof JSONArray){

                    tmpArry = (JSONArray) tmp.getArray("secrets");

                    // Go through each entry of the array
                    for (int i = 0; i < tmpArry.size(); i++){
                        if(tmpArry.getObject(i).getString("user").equals(userName)){
                            password = tmpArry.getObject(i).getString("secret");
        
                            break;
                        } 

                        if(!tmpArry.getObject(i).getString("user").equals(userName) && i == tmpArry.size() - 1){
                            throw new InaccessibleObjectException("User was not found");
                        }
                    }                    
                } else {
                    throw new InvalidObjectException("Expected type: JSONArray");
                }
            } else {
                throw new InvalidObjectException("Expected field: secrets");
            }
        } else {
            throw new InaccessibleObjectException("Expeted JSON object");
        }
        
        // Return the nonce as a String
        return Base64.getEncoder().encodeToString(nonce);
    }

    /**
     * Function that takes as input a String and produces a Base64 encoded hash
     * @param input
     * @return
     * @throws NoSuchAlgorithmException
     */
    private static String hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }


    /**
     * Perform the CHAP protocol between the server and client
     * @param recieve
     * @param send
     * @throws Exception
     */
    private static void runCHAP(DataInputStream recieve, DataOutputStream send) throws Exception{
        // Receive the user name and password
        userName = recieve.readUTF();
        password = recieve.readUTF();

        System.out.println("\"" + userName +"\"");
        
        String challengeString = generateChallenge(userName);
        //System.out.println(challengeString);

        // Send the challege back to the user
        send.writeUTF(challengeString);
        
        // Get the response hash from the clint
        String challengeResponse = recieve.readUTF();

        // Server side computed hash
        String expectedHash = hash(challengeString + password);

        // Check to see if the hash is the same 
        if (challengeResponse.equals(expectedHash)){
            send.writeBoolean(true);
        } else {
            send.writeBoolean(false);
        
        }
    }
    /**
     * Derives the root key from the user's password using username as salt
     * 
     * @param password
     */
    private static void deriveRootKey(String password, String salt) {
       
            try {
                SecretKeyFactory skf = SecretKeyFactory.getInstance("SCRYPT");
                ScryptKeySpec spec = new ScryptKeySpec(password.toCharArray(),
                    salt.getBytes(), 2048, 8, 1, 128);
                rootKey = skf.generateSecret(spec);

              } catch (NoSuchAlgorithmException nae) {
                    nae.printStackTrace();
              } catch (InvalidKeySpecException kse) {
                    kse.printStackTrace();
              }
    }

    /**
     * Generates a session key and returns it as a Base64 encoded String
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static String generateSessionKey() throws NoSuchAlgorithmException{

           KeyGenerator keyGen = KeyGenerator.getInstance("AES");
           keyGen.init(256);
           SecretKey sessionKey = keyGen.generateKey(); // Generate the session key
           return Base64.getEncoder().encodeToString(sessionKey.getEncoded());
    }

    /**
     * Encrypt data using a secret key
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static String encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        IV = cipher.getIV();
        return Base64.getEncoder().encodeToString(cipher.doFinal(data));
    }
    // Each client that is connected should have its own thread
    @Override
    public void run() {
        try {

            // Recieve input from the client
            DataInputStream recieve = new DataInputStream(socket.getInputStream());

            // Send input to the client
            DataOutputStream send = new DataOutputStream(socket.getOutputStream());
            
            // Run the CHAP protocol
            runCHAP(recieve, send);
            
            // Get the ticket request from the client which is the service and username
            service = recieve.readUTF();
            
            // Encrypt the session key using the root key
            deriveRootKey(password, userName);
           // sessionKey = generateSessionKey();
            //String encryptedSessionkey = encrypt(sessionKey.getBytes(), rootKey);
            //Ticket ticket = new Ticket(encryptedSessionkey, userName, service, IV, "60000", System.currentTimeMillis()); // Create a new ticket
            
            //System.out.println(ticket.serialize());
            //Send ticket data back to the client
            //send.writeUTF(ticket.serialize());
            

        } catch (Exception e) {
            
            e.printStackTrace();
        }
        
    }

}
