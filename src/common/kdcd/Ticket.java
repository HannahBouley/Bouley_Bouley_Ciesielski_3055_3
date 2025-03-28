package kdcd;
/**
 * Class that represents a ticket
 */
public class Ticket {
    
    private final String encryptedSessionKey;
    private final String clientUsername;
    private final String serviceName;
    private final String IV;
    private final long timeStamp;
    private final String validityTime;

    public Ticket(String encryptedSessionKey, String clientUSername, String serviceName, byte[] Iv, String validityTime, long timeStamp){
        this.encryptedSessionKey = encryptedSessionKey;
        this.clientUsername = clientUSername;
        this.serviceName = serviceName;
        this.IV = Iv.toString();
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
        return IV.getBytes();
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
