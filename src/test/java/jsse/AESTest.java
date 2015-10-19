package jsse;

/*
*
*    jsse is Symmetric Searchable Encryption Library in Java
*
*    jsse is developed by Sashank Dara (sashank.dara@gmail.com)
*
*    This library is free software; you can redistribute it and/or
*    modify it under the terms of the GNU Lesser General Public
*    License as published by the Free Software Foundation; either
*    version 2.1 of the License, or (at your option) any later version.
*
*    This library is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
*    Lesser General Public License for more details.
*
*    You should have received a copy of the GNU Lesser General Public
*    License along with this library; if not, write to the Free Software
*    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*
**/

import junit.framework.TestCase;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class AESTest extends TestCase {

    SecretKeySpec keySpec;

    public void setUp() throws Exception {
        super.setUp();
        String password = "test"; // NOT FOR PRODUCTION
        Security.addProvider(new BouncyCastleProvider());

        keySpec = null;
        try {
            keySpec = SSEUtil.getSecretKeySpec(password, SSEUtil.getRandomBytes(16));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

    public void tearDown() throws Exception {
        super.tearDown();
    }

    public void testDeterministic() throws Exception {
        try {
            System.out.println("Test Deterministic");

            BlockCipher blockCipher = new AES("AES/ECB/PKCS7Padding", keySpec);

            byte[] plainBytes = "Hello".getBytes();
            byte[] cipherText = blockCipher.encrypt(plainBytes);
            byte[] plainText = blockCipher.decrypt(cipherText);

            if (Arrays.equals(plainBytes, plainText))
                assertTrue("Deterministic Encryption Works" , true);
            else
                assertTrue("Deterministic Encryption Fails", false);
        }
        catch (Exception e){
            assertTrue("Deterministic Encryption Does not Work" + e.getMessage() , false);
        }

    }

    public void testRandomized() throws Exception {
        try {
            System.out.println("Test Randomized");
            SecureRandom random = new SecureRandom();
            byte[] ivBytes = new byte[16];
            random.nextBytes(ivBytes);

            AES randCipher = new AES("AES/CBC/PKCS7Padding", keySpec,ivBytes);

            byte[] plainBytes = Base64.encode("10.20.30.40".getBytes());
            // byte[] idBytes = ByteBuffer.allocate(16).putLong(1).array();
            // ivBytes = SSEUtil.xorTwoByteArrays(ivBytes, idBytes);

            byte[] idIvBytes = randCipher.getIvBytes(1L);
            byte[] cipherBytes = randCipher.encrypt(plainBytes, idIvBytes);
            byte[] decryptBytes = randCipher.decrypt(cipherBytes, idIvBytes);

            if (Arrays.equals(plainBytes, decryptBytes))
                assertTrue("Randomized Encryption Works" , true);
            else
                assertTrue("Randomized Encryption Fails", false);
        }
        catch (Exception e){
            assertTrue("Randomized Encryption Does not Work" + e.getMessage() , false);
        }

    }
    public void testBoundaries() throws Exception{
        try {
            System.out.println("Test Boundaries");

            BlockCipher blockCipher = new AES("AES/ECB/NoPadding", keySpec);

            byte[] plainBytes = "CAPTURE-THE-FLAG".getBytes();
            byte[] cipherBytes = blockCipher.encrypt(plainBytes);
            byte[] plainText = blockCipher.decrypt(cipherBytes);

            if (Arrays.equals(plainBytes, plainText))
                assertTrue("Deterministic Encryption Works" , true);
            else
                assertTrue("Deterministic Encryption Fails", false);

            if(cipherBytes.length == 16 )
                assertTrue("Boundary Check Works" , true);
            else
                assertTrue("Boundary Check Fails" , false);

            blockCipher = new AES("AES/ECB/PKCS7Padding", keySpec);

            plainBytes = "CAPTURE-THE-FLAG".getBytes();
            cipherBytes = blockCipher.encrypt(plainBytes);

            if(cipherBytes.length == 32 )
                assertTrue("Boundary Check Works" , true);
            else
                assertTrue("Boundary Check Fails" , false);

            byte[] tmpCipherBytes;
            plainBytes = "CAPTURE-THE-FLAG1".getBytes();
            tmpCipherBytes = blockCipher.encrypt(plainBytes);


            if(Arrays.equals(Arrays.copyOfRange(cipherBytes,0,16),Arrays.copyOfRange(tmpCipherBytes,0,16)) )
                assertTrue("Cipher Prefix Matches" , true);
            else
                assertTrue("Cipher Prefix Does not Match" , false);


            /*
            blockCipher = new AES("AES/CBC/PKCS5Padding", keySpec);

            plainBytes = "CAPTURE-THE-FLAG".getBytes();
            cipherBytes = blockCipher.encrypt(plainBytes,"0123456789012345".getBytes());

            plainBytes = "CAPTURE-THE-FLAG1".getBytes();
            tmpCipherBytes = blockCipher.encrypt(plainBytes, "0123456789012345".getBytes());


            if(Arrays.equals(Arrays.copyOfRange(cipherBytes,0,16),Arrays.copyOfRange(tmpCipherBytes,0,16)) )
                assertTrue("Cipher Prefix Matches" , true);
            else
                assertTrue("Cipher Prefix Does not Match" , false);

             */

            plainBytes = "CAPTURE-THE-FLAG0123456789012345".getBytes();
            cipherBytes = blockCipher.encrypt(plainBytes);
            plainText = blockCipher.decrypt(cipherBytes);

            if(cipherBytes.length == 48 )
                assertTrue("Boundary Check Works" , true);
            else
                assertTrue("Boundary Check Fails" , false);


        }
        catch (Exception e){
            assertTrue("Boundaries Does not Work" + e.getMessage() , false);
        }

    }
}