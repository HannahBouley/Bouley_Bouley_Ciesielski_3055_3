package client;

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.io.Console;
import java.util.Scanner;

public class KDCClient {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        //Get user input securely
        System.out.print("Enter username: ");
        String username = scanner.nextLine();

        //Secure password input handling
        Console console = System.console();
        char[] passwordChars;
        if (console != null) {
            passwordChars = console.readPassword("Enter password: ");
        } else {
            System.out.print("Enter password (input hidden not supported): ");
            passwordChars = scanner.nextLine().toCharArray();
        }
        String password = new String(passwordChars);

        //Hash the password securely with PBKDF2
        byte[] salt = generateSalt();
        byte[] hashedPassword = hashPassword(password, salt);

        //Encrypt the hashed password using AES
        SecretKey secretKey = generateAESKey();
        IvParameterSpec iv = generateIV();
        String encryptedPassword = encrypt(hashedPassword, secretKey, iv);

        //Output encrypted data
        System.out.println("\nUsername: " + username);
        System.out.println("Salt (Base64): " + Base64.getEncoder().encodeToString(salt));
        System.out.println("Encrypted Hashed Password: " + encryptedPassword);
        System.out.println("Secret Key (Base64): " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        System.out.println("IV (Base64): " + Base64.getEncoder().encodeToString(iv.getIV()));

        //Decrypt the hashed password
        byte[] decryptedHash = decrypt(encryptedPassword, secretKey, iv);
        System.out.println("\nDecrypted Hashed Password: " + Base64.getEncoder().encodeToString(decryptedHash));

        //Clear password from memory
        java.util.Arrays.fill(passwordChars, '\0');

        scanner.close();
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

}
