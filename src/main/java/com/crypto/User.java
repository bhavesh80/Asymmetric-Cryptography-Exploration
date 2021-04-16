package com.crypto;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import org.json.JSONObject;
import org.apache.commons.io.FileUtils;

public class User extends GenerateKey{

    public String receiverFilePath = null;
    public String inputFile = super.basePath + super.id + "\\jsonData.txt";

    public User(String[] args) {
        super(args);
        this.receiverFilePath = super.basePath + super.receiverUserId ;
    }

    public String message(String msg){
        return "returned from message() " +msg;
    }

    public String generateJson() throws IOException {
        JSONObject obj = new JSONObject();
        obj.put("id", "123");
        obj.put("name", "bhavesh");
        obj.put("phone_no", "1234567890");
        obj.put("id", "123");
        obj.put("name", "bhavesh");
        obj.put("phone_no", "1234567890");
        obj.put("id", "123");
        obj.put("name", "bhavesh");
        obj.put("phone_no", "1234567890");
        System.out.println("JSON Data : "+obj);
        try (FileWriter out = new FileWriter(inputFile)) {
            out.write(obj.toString());
        }
        return obj.toString();
    }

    public void sendFiletoUser(String srcPath) throws IOException {
        File src = new File(srcPath);
        File dest = new File(this.receiverFilePath);
        FileUtils.copyFileToDirectory(src, new File(this.receiverFilePath));
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
                    System.out.println("    = decryptdata   #{filename}       Decrypt data ");
                    System.out.println("    = validate  #{filename}       Validate data");
                    System.out.println("Generate KeyPairs");
                    System.out.println("    = generate keypairs");
                }else if (args[0].equals("sendfile") && args[1].equals("-user") && args[2] != null && args[3] != null) {
                    if (currentUserId == null){
                        System.out.println("User not logged in");
                    }else{
                        params[4] = currentUserId;
                        System.out.println("File sending...");
//                        GenerateKey genKey = new GenerateKey(params);
//                        genKey.generateRSAKeys();
                        Sender sender = new Sender(params);
//                        sender.printKeys();
                        User u = new User(params);
                        u.generateJson();
                        String encryptedFile = sender.generateAESKeyandSignData();
                        u.sendFiletoUser(encryptedFile);
                        System.out.println("Completed");
                    }
                }else if (args[0].equals("decryptdata")){
                    params[4] = currentUserId;
                    System.out.println("Decrypting data...");
                    Receiver receiver = new Receiver(params);
                    receiver.decryptData();
                    System.out.println("Completed");

                }else if (args[0].contains("generate") && args[1].contains("keypair")){
                    params[4] = currentUserId;
                    if (currentUserId != null){
                        GenerateKey genKey = new GenerateKey(params);
                        genKey.generateRSAKeys();
                        System.out.println("Public and Private Keys generated");
                    }else{
                        System.out.println("User not logged in");
                    }
                }else if (args[0].contains("exit")){
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
