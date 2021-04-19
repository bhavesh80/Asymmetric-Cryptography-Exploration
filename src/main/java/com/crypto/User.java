package com.crypto;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.json.JSONArray;
import org.json.JSONObject;

public class User extends KeyOperation {

    public String receiverFilePath = null;
    public String inputFile = super.basePath + super.id + "\\jsonData.txt";

    public User(String[] args) {
        super(args);
        this.receiverFilePath = super.basePath + super.receiverUserId ;
    }

    public String generateJson() throws IOException {
        JSONObject obj = new JSONObject();
        JSONArray array = new JSONArray();
        obj.put("id", "1423");
        obj.put("name", "Alice");
        obj.put("phone_no", "1234567893");
        obj.put("user_name", "user_alice");
        obj.put("password", "alice123!@#");
        System.out.println("JSON Data : "+obj);
        try (FileWriter out = new FileWriter(inputFile)) {
            out.write(obj.toString());
        }
        return obj.toString();
    }

    /**
    *   Note : args is used to take commands from commandline. Commands are as follow
     *   1. help
     *   2. login {user_id}
     *   3. generate keypair
     *   4. sendData -to_user {receiver_userid}
     *   5. decryptData -from_user {sender_userid}
     *   6. exit
     */
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        String currentUserId = null;

        System.out.println("-------------------");
        System.out.println("Crytography - Encryption and Decryption using RSA & AES.");
        System.out.println("Type 'help' to list all commands.");
        System.out.println("-------------------");
        while(true) {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String argsString = reader.readLine();
            args = argsString.split(" ");
            String[] params = Arrays.copyOf(args, 10);

            try {
                if (args[0].contains("help")) {
                    System.out.println("-------------------");
                    System.out.println("List of all Commmands");
                    System.out.println("Login User");
                    System.out.println("    = login userid                              Login user with userid");
                    System.out.println("Encrypt and send data to user");
                    System.out.println("    = sendData -to_user {userId}                Encrypt and send data to user");
                    System.out.println("Decrypt and verify data");
                    System.out.println("    = decryptData -from_user {receiver_userid}  Decrypt data received from specifc user");
                    System.out.println("Generate KeyPairs");
                    System.out.println("    = generate keypairs                         Generate RSA Key pair for logged in User");
                }
                else if (args[0].contains("login") && args[1] != null) {
                        currentUserId = args[1];
                        System.out.println("User Id : " + currentUserId + " login successful");
                }
                else if (args[0].equalsIgnoreCase("sendData") && args[1].equalsIgnoreCase("-to_user") && args[2] != null) {
                    if (currentUserId == null){
                        System.out.println("User not logged in");
                    }else{
                        params[4] = currentUserId;
                        User u = new User(params);
                        String jsonInput = u.generateJson();
                        Sender sender = new Sender(params);
                        sender.startEncryption(params,jsonInput);

                        System.out.println("Task Completed");
                    }
                }else if (args[0].equalsIgnoreCase("decryptData") && args[1].equalsIgnoreCase("-from_user") && args[2] != null){
                    params[4] = currentUserId;
                    if (currentUserId != null) {
                        System.out.println("Decrypting data...");
                        Receiver receiver = new Receiver(params);
                        receiver.startDecryption();
                        System.out.println("Task Completed");
                    }else{
                        System.out.println("User not logged in");
                    }

                    System.out.println("Completed");
                }else if (args[0].equalsIgnoreCase("generate") && args[1].equalsIgnoreCase("keypair")){
                    params[4] = currentUserId;
                    if (currentUserId != null){
                        KeyOperation genKey = new KeyOperation(params);
                        genKey.generateRSAKeys();
                        System.out.println("Public and Private Keys generated");
                    }else{
                        System.out.println("User not logged in");
                    }
                }else if (args[0].equalsIgnoreCase("exit")){
                    System.out.println("Exiting...");
                    return;
                }else{
                }
            }catch(Exception e){
                System.out.println("Invalid Command - Type help to list all commands");
                e.printStackTrace();
            }

        }


        }
}
