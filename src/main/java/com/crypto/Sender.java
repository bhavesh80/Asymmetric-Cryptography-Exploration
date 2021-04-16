package com.crypto;

import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Sender extends GenerateKey  {

    String publicKeyPath;
    String privateKeyPath;
    String receiverKeyPath;

    public Sender(String[] args) {
        super(args);
    }

    public PrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
        Path path = Paths.get(super.privateKeyPath);
        byte[] bytes = Files.readAllBytes(path);

        /* Generate private key. */
        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey pvt = kf.generatePrivate(ks);
        return pvt;
    }

        public PublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
            Path path = Paths.get(super.publicKeyPath);
            byte[] bytes = Files.readAllBytes(path);

            /* Generate public key. */
            X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey pub = kf.generatePublic(ks);
            return pub;
        }

        public void printKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
                KeyPair kp = new KeyPair(getPublicKey(),getPrivateKey());
                PublicKey pub = kp.getPublic();
                PrivateKey pvt = kp.getPrivate();
                System.out.println("Public key : " + getHexString(pub.getEncoded()));
                System.out.println("Private key : " + getHexString(pvt.getEncoded()));
        }

    private String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
        }
        return result;
    }


    public String getSHA256Hash(String data) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(data.getBytes("UTF-8"));
        System.out.println("JSON To HASH :"+bytesToHex(hash));
        return bytesToHex(hash); // make it printable
    }

    private String  bytesToHex(byte[] hash) {
        return DatatypeConverter.printHexBinary(hash);
    }



}
