package com.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class GenerateKey {

    public String basePath = "D:\\crytography\\user\\";
    public String id;
    public String publicKeyPath ;
    public String privateKeyPath ;
    public String receiverPublicKey;
    public String receiverUserId ;


    public GenerateKey(String[] args) {
        this.id = args[4];
        this.receiverUserId = args[2];
        this.publicKeyPath = basePath + id + "\\public.pub";
        this.privateKeyPath = basePath + id + "\\private.key";
        this.receiverPublicKey = basePath + args[2] + "\\public.pub";
        createUserDirectory(basePath+id);
        createUserDirectory(basePath+args[2]);

    }


    public void createUserDirectory(String dir){
        File f = new File(basePath+id);
        if (!f.isDirectory()){
            f.mkdir();
        }
    }
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

    public PrivateKey getPrivateKey(String keyPath) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        Path path = Paths.get(keyPath);
        byte[] bytes = Files.readAllBytes(path);

        /* Generate private key. */
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks);
        return pvt;
    }

    public PublicKey getPublicKey(String keyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Path path = Paths.get(keyPath);
        byte[] bytes = Files.readAllBytes(path);

        /* Generate public key. */
        X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey pub = kf.generatePublic(ks);
        return pub;
    }



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
        return "success";
    }


}
