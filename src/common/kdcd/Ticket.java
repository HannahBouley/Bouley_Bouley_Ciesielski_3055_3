package kdcd;

import java.util.Base64;

/**
 * Class that represents a ticket
 */
public class Ticket {
    
    private final String encryptedSessionKey;
    private final String clientUsername;
    private final String serviceName;
    private final byte[] IV;
    private final long timeStamp;
    private final String validityTime;

<<<<<<< HEAD
    public Ticket(String encryptedSessionKey, String clientUSername, String serviceName, byte[] Iv, String validityTime, long timeStamp) {
        // Null check for constructor parameters
        if (encryptedSessionKey == null || clientUSername == null || serviceName == null || Iv == null) {
            throw new IllegalArgumentException("One or more required fields are null");
        }
=======
    public Ticket(String encryptedSessionKey, String clientUSername, String serviceName, byte[] Iv, String validityTime, long timeStamp){
>>>>>>> 7ecfe897bdc02a5431cc3fbe12ee738c6982db59
        this.encryptedSessionKey = encryptedSessionKey;
        this.clientUsername = clientUSername;
        this.serviceName = serviceName;
        this.IV = Iv;
        this.timeStamp = timeStamp;
<<<<<<< HEAD
        this.validityTime = validityTime;
=======
        this.validityTime =validityTime;
    
>>>>>>> 7ecfe897bdc02a5431cc3fbe12ee738c6982db59
    }

    /**
     * Get the session key encrypted
     * @return
     */
    public String getEncryptedSessionKey(){
        return encryptedSessionKey;
    }

    /**
     * Gets the client's user name
     * @return
     */
    public String getClientUserName(){
        return clientUsername;
    }

    /**
     * Get the service
     * @return
     */
    public String getService(){
        return serviceName;
    }

    /**
     * Get the iv used
     * @return
     */
    public byte[] getIv(){
        return IV;
    }

    /**
     * Get the validity time
     * @return
     */
    public String getValidityTime(){
        return validityTime;
    }

    /**
     * Get the time stamp
     * @return
     */
    public long getTimeStamp(){
        return timeStamp;
    }

    /**
     * Serializes ticket data into a form that it can be transported
     * @return
     */
<<<<<<< HEAD
    public String serialize() {
        // Null check for IV before Base64 encoding
        if (IV == null) {
            throw new IllegalArgumentException("IV is null");
        }

        String encodedIV = Base64.getEncoder().encodeToString(IV);


        String serialized = encryptedSessionKey + "," +
                            clientUsername + "," +
                            serviceName + "," +
                            encodedIV + "," +  
                            validityTime + "," +
                            timeStamp;

        return serialized;
    }

    
    /**
     * Gets ticket data from a serialized form
=======
    public String serialize(){
        return encryptedSessionKey + "," + clientUsername + "," + serviceName + "," + IV + "," + validityTime + "," + String.valueOf(timeStamp);
    }

    /**
     * Gets ticket data from a serialized from
>>>>>>> 7ecfe897bdc02a5431cc3fbe12ee738c6982db59
     * @param data
     * @return
     */
    public static Ticket deserialize(String data) {
<<<<<<< HEAD
        
        String[] parts = data.split(",");
        if (parts.length != 6) {
            throw new IllegalArgumentException("Invalid ticket format: " + data);
        }

        String ivBase64 = parts[3].trim();

        if (ivBase64 == null || ivBase64.isEmpty()) {
            throw new IllegalArgumentException("IV in serialized data is null or empty");
        }

        ivBase64 = ivBase64.replaceAll("[^A-Za-z0-9+/=]", "");
        

        byte[] decodedIV;
        try {
            decodedIV = Base64.getDecoder().decode(ivBase64);
        } catch (IllegalArgumentException e) {
            System.out.println("ERROR: Failed to decode IV! Invalid Base64 format.");
            throw e;
        }

        return new Ticket(
            parts[0],
            parts[1],
            parts[2],
            decodedIV,
            parts[4],
            Long.parseLong(parts[5])
        );
    }
}
=======
        String[] parts = data.split(",");
        return new Ticket(parts[0], parts[1], parts[2], Base64.getDecoder().decode(parts[3]), parts[4], Long.parseLong(parts[5]));
    }
}
>>>>>>> 7ecfe897bdc02a5431cc3fbe12ee738c6982db59
