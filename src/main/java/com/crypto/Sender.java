package com.crypto;

import org.apache.commons.io.FileUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.security.*;
import java.util.Base64;

public class Sender extends KeyOperation {


    public Sender(String[] args) {
        super(args);
    }

    String algorithm = "AES/CBC/PKCS5Padding";
    String encryptedFilePath = super.basePath + super.id + "\\encryptedData.txt";
    String receiverFilePath = super.basePath + super.receiverUserId + "\\" ;

    /**
    *   Encrypt data using Receiver Public key
     */
    public String encryptData(String plainText, PublicKey publicKey) throws Exception {
        Cipher encryptCipher = Cipher.getInstance("RSA");
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] cipherText = encryptCipher.doFinal(plainText.getBytes("UTF-8"));

        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     *  Sign Json Data and return base64 encoded signature
     */
    public String signData(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes("UTF-8"));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    /**
     *  Encrypt JsonData + Signature using AES encryption and return base64 of combined json+signature encrypted.
     */
    public static String aesEncrypt(String algorithm, String input, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     *  Copy Encrypted Data to receiver directory
     */
    public void sendFiletoUser(String srcPath, String desPath) throws IOException {
        File src = new File(srcPath);
        File dest = new File(desPath);
        FileUtils.copyFileToDirectory(src, new File(desPath));
    }


    /**
    *    Note : Encrypted Output file contains data in following order
     *           All are saved encoded using BASE64
     *    1.    Data & Signature encrypted using AES encryption
     *    2.    AES KEY Encrypted using public key of receiver
     *    3.    Initialization vector
     *    4.    Public Key of sender
     */

    public String startEncryption(String[] params, String jsonInput) throws Exception {
        String signature = null;
        String input_signature = null;
        String final_data = null;

        try {
            System.out.println("---------------------Reading keys------------------------");
            KeyOperation genKey = new KeyOperation(params);
            PublicKey pub = genKey.getPublicKey();
            PublicKey pubReceiver = genKey.getReceiverPublicKey();
            PrivateKey pvt = genKey.getPrivateKey();
            System.out.println("---------------------------------------------------------");

            System.out.println("-----------Reading public key into base64 ---------------");
            byte[] encodedPublicKey = pub.getEncoded();
            String b64PublicKey = Base64.getEncoder().encodeToString(encodedPublicKey);
            System.out.println("Base64 public key : " + b64PublicKey);
            System.out.println("---------------------------------------------------------");


            System.out.println("----------- Signing file with own private key -----------");
            System.out.println("input data : " + jsonInput);
            signature = signData(jsonInput, pvt);
            System.out.println("Signature  : " + signature);
            input_signature = jsonInput + "|--|" + signature;
            System.out.println("---------------------------------------------------------");


            System.out.println("----------------------AES ENCRYPTION---------------------");
            SecretKey aesKey = genKey.generateAESKey(128);

            String encodedAESKey = Base64.getEncoder().encodeToString(aesKey.getEncoded());
            System.out.println("AES KEY ENCODED - " + encodedAESKey);

            byte[] byteInitVector = genKey.generateIv();
            IvParameterSpec ivParameterSpec = new IvParameterSpec(byteInitVector);
            String b64IniVector = Base64.getEncoder().encodeToString(byteInitVector);
            System.out.println("Base64 Initialization Vector : " + b64IniVector);

            String dataEncryptedAES = aesEncrypt(algorithm, input_signature, aesKey, ivParameterSpec);
            System.out.println("Encrypted Text : " + dataEncryptedAES);
            System.out.println("---------------------------------------------------------");


            System.out.println("-------------------Encrypting AES KEY--------------------");
            String aesEncrypted = encryptData(encodedAESKey, pubReceiver);
            System.out.println("Encrypted AES Key : " + aesEncrypted);
            System.out.println("---------------------------------------------------------");

            System.out.println("Combining AES ENCRYPTED(json  + signature) + Receiver Public Key(ENCRYPTED AES KEY)");
            final_data = dataEncryptedAES + "|--|" + aesEncrypted + "|--|" + b64IniVector + "|--|" + b64PublicKey;
            System.out.println(final_data);
            System.out.println("----------------------------");


            File output = new File(encryptedFilePath);
            FileWriter writer = new FileWriter(output);
            writer.write(final_data);
            writer.flush();
            writer.close();

            sendFiletoUser(encryptedFilePath, receiverFilePath);

            File sentFile = new File(receiverFilePath + "encryptedData.txt");

            if (output != null && output.exists() && sentFile.exists()) {
                return "Data encrypted and sent successfully";
            }
            return "something went wrong";
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "Something went wrong";
    }

}
