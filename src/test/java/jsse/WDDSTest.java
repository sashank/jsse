package jsse;

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.spec.SecretKeySpec;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;

/**
 * Created by Sashank Dara on 06/10/15.
 */
public class WDDSTest extends TestCase {
    private String password;
    private SecretKeySpec secretKeySpec;
    private WDDS searchableCipher;
    private String plainText;

    public void setUp() throws Exception {
        super.setUp();
        password = "test"; // NOT FOR PRODUCTION
        Security.addProvider(new BouncyCastleProvider());
        secretKeySpec = SSEUtil.getSecretKeySpec(password,
                SSEUtil.getRandomBytes(20));
        searchableCipher = new WDDS(secretKeySpec,"AES",128,SSEUtil.getRandomBytes(16)) ;
    }

    public void tearDown() throws Exception {
        super.tearDown();
    }

    public void testCipher() throws Exception {
        plainText = "Hello";
        byte cipherBytes[] = searchableCipher.encrypt(plainText.getBytes());
        byte plainBytes[]  = searchableCipher.decrypt(cipherBytes);

        if(Arrays.equals(plainBytes, plainText.getBytes()))
            assertTrue("Encryption works",true);

    }


    public void testBlindMatch() throws Exception {
        testCipher();

        byte[] trapDoorBytes = searchableCipher.getTrapDoor(plainText.getBytes());
        byte[] bBytes = searchableCipher.getBBytes(plainText.getBytes());

        if(searchableCipher.isMatch(trapDoorBytes,bBytes))
            assertTrue("Blind Match works",true);
        else
            assertFalse("Blind Match Failed",true);
    }


}