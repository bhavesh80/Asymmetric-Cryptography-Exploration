package com.crypto;

import javax.crypto.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class KeyOperation {

    public String basePath = "D:\\crytography\\user\\";
    public String id;
    public String publicKeyPath ;
    public String privateKeyPath ;
    public String receiverPublicKey;
    public String receiverUserId ;

    public KeyOperation(String[] args) {
        this.id = args[4];
        this.receiverUserId = args[2];
        this.publicKeyPath = basePath + id + "\\public.pub";
        this.privateKeyPath = basePath + id + "\\private.key";
        this.receiverPublicKey = basePath + args[2] + "\\public.pub";
        createUserDirectory(basePath+id);
        createUserDirectory(basePath+args[2]);
    }

    /**
     *  Check sender and receiver directory , if not exists then created
     */
    public void createUserDirectory(String dir){
        File f = new File(basePath+id);
        if (!f.isDirectory()){
            f.mkdir();
        }
    }

    /**
     *  Check if RSA KeyPair exits
     */
    public boolean isKeyPairExists(){
        File pvtKeyFile = new File(this.privateKeyPath);
        File pubKeyFile = new File(this.privateKeyPath);

        if (!pvtKeyFile.exists() || !pubKeyFile.exists()){
            System.out.println("Either key missing");
            return false;
        }else{
            System.out.println("KeyPair Exists");
            return true;
        }
    }

    /**
     *  Read RSA private key from filename.key and convert to PrivateKey object
     */
    public PrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        String keyPath = this.privateKeyPath;
        Path path = Paths.get(keyPath);
        byte[] bytes = Files.readAllBytes(path);

        /* Generate private key. */
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks);
        return pvt;
    }

    /**
     *  Read RSA Public key from filename.pub and convert to PublicKey object
     */
    public PublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String keyPath = this.publicKeyPath;
        Path path = Paths.get(keyPath);
        byte[] bytes = Files.readAllBytes(path);

        /* Generate public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);
        return pub;
    }

    /**
     *  Read RSA Public key of Receiver from filename.pub and convert to PublicKey object
     */
    public PublicKey getReceiverPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String keyPath = this.receiverPublicKey;
        Path path = Paths.get(keyPath);
        byte[] bytes = Files.readAllBytes(path);

        /* Generate Receiver public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);
        return pub;
    }

    /**
     *  Generate RSA keyPair i.e public key public.pub and private.key
     */
    public String generateRSAKeys() throws
            NoSuchAlgorithmException,
            java.io.IOException
    {
        boolean keysExists = isKeyPairExists();
        if (!keysExists){
            System.out.println("Generating Keys");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            Key pub = kp.getPublic();
            Key pvt = kp.getPrivate();

            try (FileOutputStream out = new FileOutputStream( this.privateKeyPath)) {
                out.write(pvt.getEncoded());
                out.close();
            }
            try (FileOutputStream out = new FileOutputStream(this.publicKeyPath)) {
                out.write(pub.getEncoded());
                out.close();
            }
            System.out.println("Private key format: " + pvt.getFormat());
            System.out.println("Public key format: " + pub.getFormat());
            return "success";
        }
        return "failed";
    }


    /**
     *  Generate AES key and return object of SecretKey containing AES key
     */
    public SecretKey generateAESKey(int n) throws NoSuchAlgorithmException, IOException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        return key;
    }

    /**
     *  Generate Initialization Vector byte for AES key and return byte value of IV
     */
    public  byte[] generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}
