package jsse;

import com.cisco.fnr.FNRUtils;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.lang.reflect.Field;
import java.security.Security;
import java.util.Arrays;

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

public class SWPTest
    extends TestCase
{
    private String password;

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public SWPTest (String  testName)

    {
        super( testName );
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite()
    {
        return new TestSuite( SWPTest.class );
    }

    public void setUp() throws Exception {
        super.setUp();

        password = "test"; // NOT FOR PRODUCTION
        Security.addProvider(new BouncyCastleProvider());
    }


    public void tearDown() throws Exception {
        super.tearDown();
    }

    /**
     * Rigourous Test :-)
     * Searchable without False Positives
     * Notice that the load factor is 1
     */
    public void testSWP_NO_FP_AES() {
        System.out.println("Test AES Searchable ");

        double loadFactor = 1; // No false positives but additional storage
         try {
             SWP swp = new SWP(SSEUtil.getSecretKeySpec(password,
                     SSEUtil.getRandomBytes(20)), "AES",loadFactor, 128);

             byte[] plainBytes = ("Hello").getBytes();
             byte[] cipherText = swp.encrypt(plainBytes, 1);

             if(cipherText.length == 2 * SWP.BLOCK_BYTES)
                 assertTrue("Additional Storage", true);
             else
                 assertTrue("Strange",false);

             byte[] plainText = swp.decrypt(cipherText, 1);

             if (Arrays.equals(plainBytes, plainText))
                 assertTrue("Encryption and Decryption works !",true);
             else
                 assertTrue("Failed", false);

             // Get Trapdoor
             byte[] trapDoor = swp.getTrapDoor(plainBytes);

             // Check Match
             if (swp.isMatch(trapDoor, cipherText))
                 assertTrue("Matching works Blind-foldedly !",true);
             else
                 assertTrue("Matching Does not work !", false);


         } catch (Exception e){
             e.printStackTrace();
             assertTrue("Something went wrong .. some where !!! .." + e.getMessage(),false);
         }
    }
    public void testSWP_NO_FP_FNR() {
        System.out.println("Test FNR Searchable String ");

        double loadFactor = 1; // No false positives but additional storage
         try {
             String givenText = "Hello " ;

             byte[] plainBytes = FNRUtils.rankIPAddress(givenText);

             SWP swp = new SWP(SSEUtil.getSecretKeySpec(password,
                     SSEUtil.getRandomBytes(20)), "FNR",loadFactor, plainBytes.length*Byte.SIZE);


             byte[] cipherBytes = swp.encrypt(plainBytes, 1);

             if(cipherBytes.length == 2 * SWP.BLOCK_BYTES)
                 assertTrue("Additional Storage", true);
             else
                 assertTrue("Strange",false);

             byte[] decryptBytes = swp.decrypt(cipherBytes, 1);


             if (Arrays.equals(plainBytes, decryptBytes))
                 assertTrue("Encryption and Decryption works !",true);
             else
                assertTrue("Failed", false);

             // Get Trapdoor
             byte[] trapDoor = swp.getTrapDoor(plainBytes);

             // Check Match
             if (swp.isMatch(trapDoor, cipherBytes))
                 assertTrue("Matching works Blind-foldedly !",true);
             else
                 assertTrue("Matching Does not work !", false);


         } catch (Exception e){
             e.printStackTrace();
             assertTrue("Something went wrong .. some where !!! .." + e.getMessage(),false);
         }
    }
    public void testSWP_NO_FP_FNR_IP() {
        System.out.println("Test FNR Searchable IP Address ");

        double loadFactor = 1; // No false positives but additional storage
         try {
             String givenIp = "192.168.1.1" ;
             System.out.println("IPAddress " + givenIp);
             byte[] plainBytes = FNRUtils.rankIPAddress(givenIp);

             SWP swp = new SWP(SSEUtil.getSecretKeySpec(password,
                     SSEUtil.getRandomBytes(20)), "FNR",loadFactor, plainBytes.length*Byte.SIZE);


             byte[] cipherBytes = swp.encrypt(plainBytes, 1);

             if(cipherBytes.length == 2 * SWP.BLOCK_BYTES)
                 assertTrue("Additional Storage", true);
             else
                 assertTrue("Strange",false);

             byte[] decryptBytes = swp.decrypt(cipherBytes, 1);


             if (Arrays.equals(plainBytes, decryptBytes))
                 assertTrue("Encryption and Decryption works !",true);
             else
                assertTrue("Failed", false);

             // Get Trapdoor
             byte[] trapDoor = swp.getTrapDoor(plainBytes);

             // Check Match
             if (swp.isMatch(trapDoor, cipherBytes))
                 assertTrue("Matching works Blind-foldedly !",true);
             else
                 assertTrue("Matching Does not work !", false);


         } catch (Exception e){
             e.printStackTrace();
             assertTrue("Something went wrong .. some where !!! .." + e.getMessage(),false);
         }
    }

    /**
     * Rigourous Test :-)
     * SWP With no additional storage
     * Search could have False Positives
     * Notice that the load factor is < 1
     */
    public void testSWP_NO_ADD_STORAGE_AES() {
        System.out.println("Test AES Searchable ");

        double loadFactor = 0.7; // No false positives but additional storage
         try {

             SWP swp = new SWP(SSEUtil.getSecretKeySpec(password,
                     SSEUtil.getRandomBytes(20)), "AES",loadFactor, 128);

             byte[] plainBytes = ("Hello").getBytes();
             byte[] cipherText = swp.encrypt(plainBytes, 1);

             if(cipherText.length != SWP.BLOCK_BYTES)
                 assertTrue("Strange",false);
             else
                 assertTrue("NO additional Storage", true);

             byte[] plainText = swp.decrypt(cipherText, 1);

             if (Arrays.equals(plainBytes, plainText))
                 assertTrue("Encryption and Decryption works !",true);
             else
                 assertTrue("Failed", false);

             // Get Trapdoor
             byte[] trapDoor = swp.getTrapDoor(plainBytes);

             // Check Match
             if (swp.isMatch(trapDoor, cipherText))
                 assertTrue("Matching works Blind-foldedly !",true);
             else
                 assertTrue("Matching Does not work !", false);


         } catch (Exception e){
             e.printStackTrace();
             assertTrue("Something went wrong .. some where !!! .." + e.getMessage(),false);
         }
    }

    public void testSWP_NO_ADD_STORAGE_FNR() {
        System.out.println("Test FNR Searchable  String");

        double loadFactor = 0.7; // No false positives but additional storage
         try {
             String givenText = "Hello" ;
             byte[] plainBytes = givenText.getBytes();

             SWP swp = new SWP(SSEUtil.getSecretKeySpec(password,
                     SSEUtil.getRandomBytes(20)), "FNR",loadFactor, plainBytes.length*Byte.SIZE);

             byte[] cipherText = swp.encrypt(plainBytes, 1);

             if(cipherText.length != SWP.BLOCK_BYTES)
                 assertTrue("Strange",false);
             else
                 assertTrue("No additional Storage", true);

             byte[] decryptBytes = swp.decrypt(cipherText, 1);

             if (Arrays.equals(plainBytes, decryptBytes))
                 assertTrue("Encryption and Decryption works !",true);
             else
                 assertTrue("Failed", false);

             // Get Trapdoor
             byte[] trapDoor = swp.getTrapDoor(plainBytes);

             // Check Match
             if (swp.isMatch(trapDoor, cipherText))
                 assertTrue("Matching works Blind-foldedly !",true);
             else
                 assertTrue("Matching Does not work !", false);


         } catch (Exception e){
             e.printStackTrace();
             assertTrue("Something went wrong .. some where !!! .." + e.getMessage(),false);
         }
    }
    public void testSWP_NO_ADD_STORAGE_FNR_IP() {
        System.out.println("Test FNR Searchable  IPAddress");

        double loadFactor = 0.7; // No false positives but additional storage
         try {
             String givenIp = "192.168.1.1" ;
             System.out.println("IPAddress " + givenIp);

             byte[] plainBytes = FNRUtils.rankIPAddress(givenIp);

             SWP swp = new SWP(SSEUtil.getSecretKeySpec(password,
                     SSEUtil.getRandomBytes(20)), "FNR",loadFactor, plainBytes.length*Byte.SIZE);

             byte[] cipheBytes = swp.encrypt(plainBytes, 1);

             String cipherIp = FNRUtils.deRankIPAddress(cipheBytes);
             System.out.println("Cipher IPAddress " + cipherIp);

             if(cipheBytes.length != SWP.BLOCK_BYTES)
                 assertTrue("Strange",false);
             else
                 assertTrue("No additional Storage", true);

             byte[] decryptBytes = swp.decrypt(cipheBytes, 1);
             String decryptedIP = FNRUtils.deRankIPAddress(decryptBytes);
             System.out.println("Decrypted IPAddress " + decryptedIP);
             if (Arrays.equals(plainBytes, decryptBytes))
                 assertTrue("Encryption and Decryption works on bytes !",true);
             else
                 assertTrue("Failed Encryption and Decryption works on bytes  ", false);

             if(givenIp.equals(decryptedIP))
                 assertTrue("Encryption and Decryption works on IP Address !",true);
             else
                 assertTrue("Failed Encryption and Decryption works on IP Address  ", false);



             // Get Trapdoor
             byte[] trapDoor = swp.getTrapDoor(plainBytes);
             System.out.println("Trapdoor IPAddress " + FNRUtils.deRankIPAddress(trapDoor));

             // Check Match
             if (swp.isMatch(trapDoor, cipheBytes))
                 assertTrue("Matching works Blind-foldedly !",true);
             else
                 assertTrue("Matching Does not work !", false);


         } catch (Exception e){
             e.printStackTrace();
             assertTrue("Something went wrong .. some where !!! .." + e.getMessage(),false);
         }
    }

    public void testLoadFactor(){
        System.out.println("Test Load factor ");
        double loadFactor= 0 ;

        try {
            new SWP(SSEUtil.getSecretKeySpec(password,
                    SSEUtil.getRandomBytes(20)), "AES",loadFactor, 128);
        }   catch (Exception e){
            assertTrue(true);
        }

        loadFactor = 2;
        try {
            new SWP(SSEUtil.getSecretKeySpec(password,
                    SSEUtil.getRandomBytes(20)), "AES",loadFactor, 128);
        }   catch (Exception e){
            assertTrue(true);
        }

        loadFactor = 1;
        try {
            new SWP(SSEUtil.getSecretKeySpec(password,
                    SSEUtil.getRandomBytes(20)), "AES",loadFactor, 128);
        }   catch (Exception e){
            assertTrue(false);
        }

        loadFactor = 0.5;
        try {
            new SWP(SSEUtil.getSecretKeySpec(password,
                    SSEUtil.getRandomBytes(20)), "AES",loadFactor, 128);
        }   catch (Exception e){
            assertTrue(false);
        }

    }
}
