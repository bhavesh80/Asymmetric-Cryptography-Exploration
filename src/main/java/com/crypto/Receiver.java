package com.crypto;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

public class Receiver extends KeyOperation {

    public Receiver(String[] args) {
        super(args);
    }

    public String encryptedFilePath = super.basePath + super.id + "\\encryptedData.txt";
    String algorithm = "AES/CBC/PKCS5Padding";

    /**
    * Decrypt encrypted AES key using receiver private key
     */
    public static String decryptData(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);
        Cipher decryptCipher = Cipher.getInstance("RSA");
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

        return new String(decryptCipher.doFinal(bytes),"UTF-8");
    }

    /**
     *  Verify jsonData with signature using sender public key
     */
    public  boolean verifyData(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes("UTF-8"));
        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    /**
     *  Decrypt received encrypted (json+signature) data (base64) and convert to plain text + signature
     */
    public static String aesDecrypt(String algorithm, String cipherText, SecretKey key,
                                    IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    /**
     *    Note : Encrypted Output file contains data in following order.
     *           All are saved encoded using BASE64
     *    1.    Data & Signature encrypted using AES encryption
     *    2.    AES KEY Encrypted using public key of receiver
     *    3.    Initialization vector
     *    4.    Public Key of sender
     */

    public String startDecryption() throws Exception {
        try{
            String final_data = new String(Files.readAllBytes(Paths.get(encryptedFilePath)));
            System.out.println("---------------Decoupling data--------------");
            System.out.println("Data read from file : "+final_data);

            String[] decoupledData = final_data.split(Pattern.quote("|--|"));
            System.out.println("--------------------------------------------");


            System.out.println("-----------Decoding Sender Public key---------");
            byte[] publicBytes = Base64.getDecoder().decode(decoupledData[3]);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey senderPublicKey = keyFactory.generatePublic(keySpec);
            System.out.println("----------------------------------------------");

            System.out.println("-----------Decoding Initialization vector-------");
            byte[] byteInitVector = Base64.getDecoder().decode(decoupledData[2]);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(byteInitVector);
            System.out.println("------------------------------------------------");

            System.out.println("---------------Decrypt AES KEY ---------------");
            String decryptedAESKey = decryptData(decoupledData[1], super.getPrivateKey());
            System.out.println(decryptedAESKey);
            System.out.println(Base64.getDecoder().decode(decryptedAESKey));
            byte[] b64aesKey = Base64.getDecoder().decode(decryptedAESKey);
            SecretKey aesKEy = new SecretKeySpec(b64aesKey, 0, b64aesKey.length, "AES");

            System.out.println("----------------------------------------------");

            System.out.println("-------Decrypting Data and signature-----------");
            String decryptedData = aesDecrypt(algorithm, decoupledData[0], aesKEy, ivParameterSpec);
            System.out.println("Decrypted data and signature : "+decryptedData);
            System.out.println("----------------------------");
            String[] decoupleDatanSignature = decryptedData.split(Pattern.quote("|--|"));

            System.out.println("decrypted json = " +decoupleDatanSignature[0]);
            System.out.println("decrypted signature = " +decoupleDatanSignature[1]);

            System.out.println("------Verify signature------");
            boolean result = verifyData(decoupleDatanSignature[0], decoupleDatanSignature[1], senderPublicKey);
            System.out.println("result : " + result);
            System.out.println("----------------------------");

            return "Something went wrong";

        }catch(Exception e){
            e.printStackTrace();
        }
        return "Something went wrong";
    }
}
