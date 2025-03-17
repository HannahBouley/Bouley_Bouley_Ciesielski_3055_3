package kdcd;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;


/**
 * The server in which the client will connect to
 */
public class KDCServer {

    private static final int POOL_SIZE = 10; // MAX NUM OF CONNECTIONS
    private static final int PORT_NUMBER = 5000; // PORT NUMBER THE SERVER IS RUNS ON

    // Entry point for the server
    public static void main(String[] args) {

        ExecutorService executor = Executors.newFixedThreadPool(POOL_SIZE);

        try(ServerSocket serverSocket = new ServerSocket(PORT_NUMBER)){
            System.out.println("Running on port " + PORT_NUMBER);

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
