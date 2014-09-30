package jsse;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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
    public void testSWP_NO_FP()
    {
        System.out.println("Test AES Searchable ");

        double loadFactor = 0.5; // No false positives but additional storage
         try {
             SWP swp = new SWP(SSEUtil.getSecretKeySpec(password,
                     SSEUtil.getRandomBytes(20)), "AES",loadFactor);

             byte[] plainBytes = ("Hello").getBytes();
             byte[] cipherText = swp.encrypt(plainBytes, 1);

             if(cipherText.length == 2 * SWP.BLOCK_BYTES)
                 assertTrue("Additional Storage", true);
             else
                 assertTrue("Strange",false);

             byte[] plainText = swp.decrypt(cipherText, 1);

             if (Arrays.equals(plainBytes, plainText))
                 assertTrue("Encryption and Decryption works !",true);

             // Get Trapdoor
             byte[] trapDoor = swp.getTrapDoor(plainBytes);

             // Check Match
             if (swp.isMatch(trapDoor, cipherText))
                 assertTrue("Matching works Blind-foldedly !",true);


             byte[] decryptTrapDoor = swp.decrypt(trapDoor);

             if (Arrays.equals(plainBytes, decryptTrapDoor))
                 assertTrue("Decrypted trap door also matches",true);

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
    public void testSWP_NO_ADD_STORAGE()
    {
        System.out.println("Test AES Searchable ");

        double loadFactor = 0.7; // No false positives but additional storage
         try {
             SWP swp = new SWP(SSEUtil.getSecretKeySpec(password,
                     SSEUtil.getRandomBytes(20)), "AES",loadFactor);

             byte[] plainBytes = ("Hello").getBytes();
             byte[] cipherText = swp.encrypt(plainBytes, 1);

             if(cipherText.length > SWP.BLOCK_BYTES)
                 assertTrue("Strange",false);
             else
                 assertTrue("Additional Storage", true);

             byte[] plainText = swp.decrypt(cipherText, 1);

             if (Arrays.equals(plainBytes, plainText))
                 assertTrue("Encryption and Decryption works !",true);

             // Get Trapdoor
             byte[] trapDoor = swp.getTrapDoor(plainBytes);

             // Check Match
             if (swp.isMatch(trapDoor, cipherText))
                 assertTrue("Matching works Blind-foldedly !",true);


             byte[] decryptTrapDoor = swp.decrypt(trapDoor);

             if (Arrays.equals(plainBytes, decryptTrapDoor))
                 assertTrue("Decrypted trap door also matches",true);

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
                    SSEUtil.getRandomBytes(20)), "AES",loadFactor);
        }   catch (Exception e){
            assertTrue(true);
        }

        loadFactor = 2;
        try {
            new SWP(SSEUtil.getSecretKeySpec(password,
                    SSEUtil.getRandomBytes(20)), "AES",loadFactor);
        }   catch (Exception e){
            assertTrue(true);
        }

        loadFactor = 1;
        try {
            new SWP(SSEUtil.getSecretKeySpec(password,
                    SSEUtil.getRandomBytes(20)), "AES",loadFactor);
        }   catch (Exception e){
            assertTrue(false);
        }

        loadFactor = 0.5;
        try {
            new SWP(SSEUtil.getSecretKeySpec(password,
                    SSEUtil.getRandomBytes(20)), "AES",loadFactor);
        }   catch (Exception e){
            assertTrue(false);
        }

    }
}
