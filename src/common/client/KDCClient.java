package client;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import kdcd.KDCServer;
import kdcd.Ticket;
import merrimackutil.cli.LongOption;
import merrimackutil.cli.OptionParser;
import merrimackutil.util.Tuple;

import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.Scanner;

public class KDCClient {

    /*
     * For reference:
     * 
     * java -jar dist/kdcclient.jar -h EchoService.java -u alice -s echoService
     */

    private static final boolean trace = false; // Toggle tracing
    
    private static String hostsFile = null;
    private static String userName = null;
    private static String service = null;
    private static String password = null;

    public static void main(String[] args) throws Exception {
        
        // First prompt user for creds
        Scanner scanner = new Scanner(System.in);

        // For reference use: alice, password --should allow access
        // For reference use: alice, badpassword --should deny access

        //Secure password input handling (no echo)
        Console console = System.console();
        char[] passwordChars;
        if (console != null) {
            passwordChars = console.readPassword("Enter password: ");
        } else {
            System.out.print("Enter password (input hidden not supported): ");
            passwordChars = scanner.nextLine().toCharArray();
        }
        password = new String(passwordChars);

        //Hash the password securely with PBKDF2
        byte[] salt = generateSalt();
        byte[] hashedPassword = hashPassword(password, salt);

        //Encrypt the hashed password using AES
        SecretKey secretKey = generateAESKey();
        IvParameterSpec iv = generateIV();
        String encryptedPassword = encrypt(hashedPassword, secretKey, iv);

        //Output encrypted data
        if (trace){
            System.out.println("\nUsername: " + userName);
            System.out.println("Salt (Base64): " + Base64.getEncoder().encodeToString(salt));
            System.out.println("Encrypted Hashed Password: " + encryptedPassword);
            System.out.println("Secret Key (Base64): " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
            System.out.println("IV (Base64): " + Base64.getEncoder().encodeToString(iv.getIV()));
        }
       
        //Decrypt the hashed password
        byte[] decryptedHash = decrypt(encryptedPassword, secretKey, iv);
        System.out.println("\nDecrypted Hashed Password: " + Base64.getEncoder().encodeToString(decryptedHash));

        //Clear password from memory
        java.util.Arrays.fill(passwordChars, '\0');

        // Clean up
        scanner.close();

        if (args.length < 1){
            // Display the help only
            System.out.println("usage:");
            System.out.println("    client --hosts <hostfile> --user <user> --service <service>");
            System.out.println("    client --user <user> --service <service>");
            System.out.println("options:");
            System.out.println("    -h, --hosts Set the hosts file.");
            System.out.println("    -u, --user The user name.");
            System.out.println("    -s, --service The name of the service");

           
        } else {
            // Handle the now opts
            handleCommandLineInputs(args);
        }

        // Start the connection with the server
        try {
            
            // The socket representing the client's end
            Socket clientSok = new Socket("127.0.0.1", 5000);

             // Set up the streams for the socket.
            DataInputStream recv = new DataInputStream(clientSok.getInputStream());
            DataOutputStream send = new DataOutputStream(clientSok.getOutputStream());

            // Send over the username and password to the server
            send.writeUTF(userName);
            send.writeUTF(password);

            // Get the nonce back from the server
            String nonce = recv.readUTF();

            //Compute the hash with the nonce and password
            String responseHash = hash(nonce + password);

            // Send over the computed hash to the server
            send.writeUTF(responseHash);
            
            // Response to user. Either valid or not.
            boolean valitated = recv.readBoolean();
            
            if (valitated){
                System.out.println("ACCESS GRANTED");

                // Ticket request from client
                send.writeUTF(service); // Send the service that the client is rquesting
                //String tikcetData = recv.readUTF(); // The resulting ticket data
                //System.out.println(tikcetData);

            } else {
                System.out.println("ACCESS DENIED");
                System.exit(1); // Kick from server
            }

           } catch (Exception e) {
                e.printStackTrace();
           }

        
    }



    //Generate a random salt
    private static byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    //Hash the password using PBKDF2
    private static byte[] hashPassword(String password, byte[] salt) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, 256);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return factory.generateSecret(spec).getEncoded();
    }

    //Generate a random AES key
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); 
        return keyGen.generateKey();
    }

    //Generate a random IV for AES
    private static IvParameterSpec generateIV() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    //Encrypt the hashed password using AES
    private static String encrypt(byte[] data, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] encryptedData = cipher.doFinal(data);
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    //Decrypt the AES-encrypted password hash
    private static byte[] decrypt(String encryptedData, SecretKey secretKey, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        return cipher.doFinal(Base64.getDecoder().decode(encryptedData));
    }

    private static String hash(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hashBytes = md.digest(input.getBytes());
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    private static void handleCommandLineInputs(String[] args){

        OptionParser optParser = new OptionParser(args);
        Tuple<Character, String> currOpt;

        optParser.setOptString("h:u:s:");

        LongOption[] longOpts = new LongOption[3];

        longOpts[0] = new LongOption("hostsFile", true, 'h');
        longOpts[1] = new LongOption("userName", true, 'u');
        longOpts[2] = new LongOption("service", true, 's');

        optParser.setLongOpts(longOpts);

        while(optParser.getOptIdx() != args.length){
            currOpt = optParser.getLongOpt(false);

            switch (currOpt.getFirst()) {
                case 'h': // The hosts file
                    hostsFile = currOpt.getSecond();
                    break;
            
                case 'u': // The user name
                    userName = currOpt.getSecond();
                    break;

                case 's': // The name of the service
                    service = currOpt.getSecond();

                    break;

                case '?': // Done with operations

                  
                    break;
                default:
                    break;
            }
        }

        

    }

}
