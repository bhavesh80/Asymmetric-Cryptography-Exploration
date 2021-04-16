package com.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;

public class GenerateKey {

    public String basePath = "D:\\crytography\\user\\";
    public String id;
    public String publicKeyPath ;
    public String privateKeyPath ;
    public String aesKeyPath ;


    public GenerateKey(String[] args) {
        this.id = args[4];
        this.publicKeyPath = basePath + id + "\\public.pub";
        this.privateKeyPath = basePath + id + "\\private.key";
        File f = new File(basePath+id);
        if (!f.isDirectory()){
            f.mkdir();
        }
    }


    static private void processFile(Cipher ci, InputStream in, OutputStream out)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            byte[] obuf = ci.update(ibuf, 0, len);
            if ( obuf != null ) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        if ( obuf != null ) out.write(obuf);
    }

    static private void processFile(Cipher ci,String inFile,String outFile)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.io.IOException
    {
        try (FileInputStream in = new FileInputStream(inFile);
             FileOutputStream out = new FileOutputStream(outFile)) {
            processFile(ci, in, out);
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

//    public String generateAESKey() throws NoSuchAlgorithmException {
//        KeyGenerator kgen = KeyGenerator.getInstance("AES");
//        kgen.init(128);
//        SecretKey skey = kgen.generateKey();
//
//        try (FileOutputStream out = new FileOutputStream( )) {
//            out.write(pvt.getEncoded());
//            out.close();
//        }
//
//
//        byte[] iv = new byte[128/8];
//        new SecureRandom().nextBytes(iv);
//        IvParameterSpec ivspec = new IvParameterSpec(iv);
//
//        return "success";
//    }

}
