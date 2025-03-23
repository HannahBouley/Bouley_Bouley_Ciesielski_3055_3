package kdcd;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
    private static final int nonceSize = 32;
    
    private static int PORT_NUMBER = 5000; // PORT NUMBER THE SERVER IS RUNS ON
    private static String secretsFile = "./test-data/kdc-config/secrets.json"; // FILE THAT HOLDS SECRETS
    private static String validityPeriod = "60000"; // THE PERIOD THAT THE TICKET IS VALID FOR
    public static NonceCache nonceCache;

    // Entry point for the server
    public static void main(String[] args) {

        // Create a new Nonce
        nonceCache = new NonceCache(nonceSize, 60000);

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

    private static void generateChallenge(String userName) throws Exception{

        // Create a new nonce
        byte[] nonce = nonceCache.getNonce();

        // Determine if the username is in the secret store
        JSONObject obj = JsonIO.readObject(new File("./test-data/kdc-config/" + secretsFile));

        JSONObject tmp;
        JSONArray tmpArry;

        if (obj instanceof JSONObject){
            tmp = (JSONObject) obj;
            
            if (tmp.containsKey("secrets")){
                
                if (tmp.getArray("secrets") instanceof JSONArray){

                    tmpArry = (JSONArray) tmp.getArray("secrets");

                    for (int i = 0; i < tmpArry.size(); i++){
                        if(tmpArry.getObject(i).getString("user").equals(userName)){
                            System.out.println("user found!");
                        }
                    }

                    
                } else {

                    throw new InvalidObjectException("Expected type: JSONArray");
                }
               

            } else {

                throw new InvalidObjectException("Expected field: secrets");
                
            }
        }



    }


    public void sendChallengeToClient(){

    }


    
}


/**
 * Handles client connections to the server
 */
class HandleClientConnections implements Runnable{
                
    private Socket socket;

    HandleClientConnections(Socket socket){
        this.socket = socket;
    }

    @Override
    public void run() {
        
        
    }

}
