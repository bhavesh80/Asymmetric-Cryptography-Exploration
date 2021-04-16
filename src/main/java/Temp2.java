//import java.io.*;
//import java.nio.file.Files;
//import java.nio.file.Path;
//import java.nio.file.Paths;
//import java.security.*;
//
//import java.io.FileOutputStream;
//import java.io.FileInputStream;
//
//import java.nio.file.Files;
//import java.nio.file.Paths;
//import java.nio.file.Path;
//
//import java.security.Key;
//import java.security.KeyPair;
//import java.security.KeyPairGenerator;
//
//import java.security.spec.InvalidKeySpecException;
//import java.security.spec.PKCS8EncodedKeySpec;
//import java.security.spec.X509EncodedKeySpec;
//
//
//public class Temp2{
//
//    public String message(String msg){
//        return "returned from message() " +msg;
//    }
//
//
//    public static String generateKeys(String[] args) throws
//            NoSuchAlgorithmException,
//            java.io.IOException
//    {
//        if ( args.length == 0 ) {
//            return "Please provide arguments to generate keys ";
//        }else if( args[0].length() == 0){
//            return "parameter filename missing";
//        }else if( args[1].length() == 0){
//            return "parameter filepath missing";
//        }else{
//            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//            kpg.initialize(2048);
//            KeyPair kp = kpg.generateKeyPair();
//            Key pub = kp.getPublic();
//            Key pvt = kp.getPrivate();
//
//            try (FileOutputStream out = new FileOutputStream(args[1] + args[0] + ".key")) {
//                out.write(pvt.getEncoded());
//                out.close();
//            }
//
//            try (FileOutputStream out = new FileOutputStream(args[1] + args[0] + ".pub")) {
//                out.write(pub.getEncoded());
//                out.close();
//            }
//            System.out.println("Private key format: " + pvt.getFormat());
//            System.out.println("Public key format: " + pub.getFormat());
//
//            return "success";
//        }
//    }
//
//    public static String getRSAKeys(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
//        Path pvtPath = Paths.get(args[1] + args[0] + ".key");
//        byte[] pvtBytes = Files.readAllBytes(pvtPath);
//
//        /* Generate private key. */
//        PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(pvtBytes);
//        KeyFactory kf = KeyFactory.getInstance("RSA");
//        PrivateKey pvt = kf.generatePrivate(ks);
//        System.out.println("private key"+pvt);
//
//        Path pubPath = Paths.get(args[1] + args[0] + ".pub");
//        byte[] pubBytes = Files.readAllBytes(pubPath);
//
//        /* Generate public key. */
//        X509EncodedKeySpec ks1 = new X509EncodedKeySpec(pubBytes);
//        KeyFactory kf1 = KeyFactory.getInstance("RSA");
//        PublicKey pub = kf1.generatePublic(ks1);
//        System.out.println("Public key"+pub);
//
//        String dataFile = "D:\\crytography\\sender\\jsonData.txt";
//        String signFile =  "D:\\crytography\\sender\\signFile";

//        /* Digital Sign document*/
//        Signature sign = Signature.getInstance("SHA256withRSA");
//        sign.initSign(pvt);
//
//        InputStream in = null;
//        try {
//            in = new FileInputStream("D:\\crytography\\sender\\jsonData.txt");
//            byte[] buf = new byte[2048];
//            int len;
//            while ((len = in.read(buf)) != -1) {
//                sign.update(buf, 0, len);
//            }
//        } finally {
//            if ( in != null ) in.close();
//        }
//
//        OutputStream out = null;
//        try {
//            out = new FileOutputStream(signFile);
//            byte[] signature = sign.sign();
//            out.write(signature);
//        } finally {
//            if ( out != null ) out.close();
//        }
//
//
//
//        /* Verifying the Digital Signature*/
//
//        sign.initVerify(pub);
//
//        InputStream input = null;
//        try {
//            input = new FileInputStream(dataFile);
//            byte[] buf = new byte[2048];
//            int len;
//            while ((len = input.read(buf)) != -1) {
//                sign.update(buf, 0, len);
//            }
//        } finally {
//            if ( input != null ) input.close();
//        }
//
//        /* Read the signature bytes from file */
//        Path path = Paths.get(signFile);
//        byte[] bytes = Files.readAllBytes(path);
//        System.out.println(dataFile + ": Signature " +
//                (sign.verify(bytes) ? "OK" : "Not OK"));
//
//        return "success";
//
//    }
//
//
//
//    public static void main(String args){
//
//    }
//}
