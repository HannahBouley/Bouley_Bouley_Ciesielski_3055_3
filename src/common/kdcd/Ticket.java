package kdcd;

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

    Ticket(String encryptedSessionKey, String clientUSername, String serviceName, byte[] Iv, String validityTime, long timeStamp){
        this.encryptedSessionKey = encryptedSessionKey;
        this.clientUsername = clientUSername;
        this.serviceName = serviceName;
        this.IV = Iv;
        this.timeStamp = timeStamp;
        this.validityTime =validityTime;

    }

    /**
     * Get the session key encrypted
     * @return
     */
    public String getEncryptedSessionKey(){
        return encryptedSessionKey;
    }

    /**
     * Get the ticket data
     * @return
     */
    public String getTicketData(){
        return clientUsername + ":" + serviceName + ":"  + timeStamp;
    }

    /**
     * Serializes ticket data into a form that it can be transported
     * @return
     */
    public String serialize(){
        return encryptedSessionKey + "," + clientUsername + "," + serviceName + "," + IV + "," + validityTime + "," + String.valueOf(timeStamp);
    }

    /**
     * Gets ticket data from a serialized from
     * @param data
     * @return
     */
    public static Ticket deserialize(String data) {
        String[] parts = data.split(",");
        return new Ticket(parts[0], parts[1], parts[2], parts[3].getBytes(), parts[4], Long.parseLong(parts[5]));
    }
}
