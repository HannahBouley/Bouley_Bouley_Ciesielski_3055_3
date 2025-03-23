package client; 

import echoservice.EchoService; // Import EchoService
import java.util.Scanner;

public class PasswordVerify {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        
        // Simulating retrieval of decrypted password hash
        System.out.print("Enter decrypted password hash: ");
        String decryptedHash = scanner.nextLine();
        
        // Sending the hash to the EchoService for verification
        EchoService echoService = new EchoService();
        boolean isValid = echoService.verifyHash(decryptedHash);
        
        // Displaying verification result
        if (isValid) {
            System.out.println("Password hash verified successfully!");
        } else {
            System.out.println("Verification failed. Hash does not match.");
        }
        
        scanner.close();
    }
}
