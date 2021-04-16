import com.crypto.User;
import org.junit.Test;
import org.junit.Assert;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;


public class CryptographyTest {
    private User user = new User();

    @Test
    public void test() throws IOException, NoSuchAlgorithmException {
        String[] args = new String[4];
        args[0] = "genkey";
        args[1] = "testFile";
        Assert.assertEquals("returned from message() testFile" , user.message(args[1]));
    }

//    @Test
//    public void testKeyGeneration() throws IOException, NoSuchAlgorithmException {
//        String[] args = new String[2];
//        args[0] = "sender";
//        args[1] = "D:\\crytography\\sender\\";
//
//        Assert.assertEquals("success", mainClass.generateRSAKeys(args));
//
//    }
//
//    @Test
//    public void testreadingKeys() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {
//        String[] args = new String[2];
//        args[0] = "sender";
//        args[1] = "D:\\crytography\\sender\\";
//
//        Assert.assertEquals("success", mainClass.getRSAKeys(args));
//
//    }


}
