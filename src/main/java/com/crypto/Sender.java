package com.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.xml.bind.DatatypeConverter;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Sender extends GenerateKey  {

    public Sender(String[] args) {
        super(args);
    }

    String publicKeyPath;
    String privateKeyPath;
    String receiverKeyPath;
    String encryptedData = super.basePath + super.id + "\\output.enc";
    String inputFile = super.basePath + super.id + "\\jsonData.txt";




    public void printKeys() throws NoSuchAlgorithmException, IOException, InvalidKeySpecException {
            KeyPair kp = new KeyPair(super.getPublicKey(super.publicKeyPath),super.getPrivateKey(super.privateKeyPath));
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


    /**
    *   Encrypted output file is divided in below parts
     *      1.  AES encryption key encrypted using receiver's public key
     *      2.  Initialization vector
     *      3.  Signature
     */
    public String generateAESKeyandSignData() throws NoSuchAlgorithmException, IOException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException {
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        gen.init(128);
        SecretKey sky = gen.generateKey();

        byte[] iv = new byte[128/8];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        FileOutputStream out = new FileOutputStream(encryptedData);
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, super.getPublicKey(super.receiverPublicKey)); // Encrypt using B's public key
            byte[] b = cipher.doFinal(sky.getEncoded());
            out.write(b);
        }

        out.write(iv);

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(super.getPrivateKey(super.privateKeyPath)); // Sign using A's private key

        Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
        ci.init(Cipher.ENCRYPT_MODE, sky, ivspec);
        try (FileInputStream in = new FileInputStream(inputFile)) {
            signFile(ci, sign, in, out);
        }
        byte[] s = sign.sign();
        out.write(s);
        out.close();

        return encryptedData;
    }



    static private void signFile(Cipher ci, Signature sign, InputStream in, OutputStream out)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.security.SignatureException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        int len;
        while ((len = in.read(ibuf)) != -1) {
            sign.update(ibuf, 0, len);
            byte[] obuf = ci.update(ibuf, 0, len);
            if ( obuf != null ) out.write(obuf);
        }
        byte[] obuf = ci.doFinal();
        if ( obuf != null ) out.write(obuf);
    }

}
