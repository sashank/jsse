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

import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class StreamCipherTest extends TestCase {

    public void setUp() throws Exception {
        super.setUp();

    }

    public void tearDown() throws Exception {

    }

    public void testStream(){
        Security.addProvider(new BouncyCastleProvider());
        byte[] saltyBytes = SSEUtil.getRandomBytes(16);
        byte[] seedBytes = SSEUtil.getRandomBytes(16);
        SecretKeySpec spec;
        try {
            spec = SSEUtil.getSecretKeySpec("OPEN_SECRET_OPEN", saltyBytes); // not for production
            boolean init = StreamCipher.init(spec);
            if(!init) {
                System.out.print("Something went wrong quitting");
                assertTrue(false);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e ) {
            e.printStackTrace();
            assertTrue(false);
        }


        byte[] randBytes1, randBytes2 ;
        try {
            randBytes1 = StreamCipher.getRandomStreamOfBytes(10, seedBytes);
            randBytes2 = StreamCipher.getRandomStreamOfBytes(10, seedBytes);

            // Test for equality

            if (Arrays.equals(randBytes1, randBytes2)) {
                System.out.println("Same");
                assertTrue(true);
            }

            randBytes1 = StreamCipher.getRandomStreamOfBytes(10, seedBytes);
            randBytes2 = StreamCipher.getRandomStreamOfBytes(11, seedBytes);

            // Test for equality
            if (!Arrays.equals(randBytes1,randBytes2)) {
                System.out.println("Not Same");
                assertTrue("Testing INEQUALITY",true);
            }

        }
        catch (Exception e){
            System.out.println("Something went wrong .. some where .." + e.getMessage());
            assertTrue(false);
        }


    }
}