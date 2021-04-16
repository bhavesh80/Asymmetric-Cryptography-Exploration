package com.crypto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.json.JSONObject;

public class User {

    public String message(String msg){
        return "returned from message() " +msg;
    }

    static public String generateJson(){
        JSONObject obj = new JSONObject();
        obj.put("id", "123");
        obj.put("name", "bhavesh");
        obj.put("phone_no", "1234567890");
        System.out.println("JSON Data : "+obj);
        return obj.toString();
    }

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
                if (args[0].contains("login")) {
                    currentUserId = args[1];
                    System.out.println("User Id : " + currentUserId + " login successful");
                }
                if (args[0].contains("help")) {
                    System.out.println("-------------------");
                    System.out.println("List of all Commmands");
                    System.out.println("Login User");
                    System.out.println("    = login userid");
                    System.out.println("Encrypt and send data to user");
                    System.out.println("    = sendfile -user #{userId} #{filename}        Encrypt and send data to user");
                    System.out.println("Decrypt and verify data");
                    System.out.println("    = checkFile #{filename}       Check if data received from sender");
                    System.out.println("    = decrypt   #{filename}       Decrypt data ");
                    System.out.println("    = validate  #{filename}       Validate data");
                }else if (args[0].equals("sendfile") && args[1].equals("-user") && args[2] != null && args[3] != null) {
                    if (currentUserId == null){
                        System.out.println("User not logged in");
                    }else{
                        params[4] = currentUserId;
                        System.out.println("File sending...");
                        GenerateKey genKey = new GenerateKey(params);
                        genKey.generateRSAKeys();
                        Sender sender = new Sender(params);
                        sender.printKeys();

                        sender.getSHA256Hash(generateJson());

                        System.out.println("Completed");
                    }
                }else if (args[0].contains("exit")){
                    System.out.println("Exiting...");
                    return;
                }
            }catch(Exception e){
                System.out.println("Invalid Command - Type help to list all commands");
                e.printStackTrace();
            }

        }


        }
}
