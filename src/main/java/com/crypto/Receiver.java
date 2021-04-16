package com.crypto;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

public class Receiver extends GenerateKey{

    public Receiver(String[] args) {
        super(args);
    }

    /**
     *             - 256       // AES Key
     *             - 16        // IV
     *             - 256;      // Signature
     */
    public String encryptedFilePath = super.basePath + super.id + "\\output.enc";
    long dataLen = new File(encryptedFilePath).length();
    public String signaturePath = super.basePath + super.id + "\\output";


    public Boolean decryptData() throws Exception {
        FileInputStream in = new FileInputStream(encryptedFilePath);
        SecretKeySpec skey = null;
        {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, super.getPrivateKey(super.privateKeyPath)); // B's private key here
            byte[] b = new byte[256];
            in.read(b);
            byte[] keyb = cipher.doFinal(b);
            skey = new SecretKeySpec(keyb, "AES");


            byte[] iv = new byte[128/8];
            in.read(iv);
            IvParameterSpec ivspec = new IvParameterSpec(iv);


            Signature ver = Signature.getInstance("SHA256withRSA");
            ver.initVerify(super.getPublicKey(super.publicKeyPath)); // Using B's public key
            Cipher ci = Cipher.getInstance("AES/CBC/PKCS5Padding");
            ci.init(Cipher.DECRYPT_MODE, skey, ivspec);
            try (FileOutputStream out = new FileOutputStream(signaturePath + ".ver")){
                authFile(ci, ver, in, out, dataLen);
            }
            byte[] s = new byte[256];
            int len = in.read(s);
            if ( ! ver.verify(s) ) {
                System.out.println("Signature not valid");
                return false;
//                throw new Exception("Signature not valid: " + Base64.getEncoder().encodeToString(s));
            }else{
                System.out.println("Signature Valid");
                return true;
            }

        }


    }

    static private void authFile(Cipher ci,Signature ver,InputStream in,OutputStream out,long dataLen)
            throws javax.crypto.IllegalBlockSizeException,
            javax.crypto.BadPaddingException,
            java.security.SignatureException,
            java.io.IOException
    {
        byte[] ibuf = new byte[1024];
        while (dataLen > 0) {
            int max = (int)(dataLen > ibuf.length ? ibuf.length : dataLen);
            int len = in.read(ibuf, 0, max);
            if ( len < 0 ) throw new java.io.IOException("Insufficient data");
            dataLen -= len;
            byte[] obuf = ci.update(ibuf, 0, len);
            if ( obuf != null ) {
                out.write(obuf);
                ver.update(obuf);
            }
        }
        byte[] obuf = ci.doFinal();
        if ( obuf != null ) {
            out.write(obuf);
            ver.update(obuf);
        }
    }

}
