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

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;


public class StreamCipher  {
    private static StreamCipher ourInstance = new StreamCipher();
    protected static Cipher cipher = null;
    protected static SecretKeySpec keySpec ;
    public static StreamCipher getInstance() {
        return ourInstance;
    }

    private StreamCipher(){

    }
    public static boolean init(SecretKeySpec spec){
        try {

            keySpec = spec;
            cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");

            return true;
        }
        catch (Exception e){
            // Do Some thing later .
        }
        return  false;
    }


    public static byte[] getRandomStreamOfBytes(long recordId, byte[] seedBytes) throws Exception {
        try {
            byte[] nonce = getNonce(recordId, seedBytes);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(nonce));
        }
        catch (Exception e){
            // do something later ;
        }

        // Plain text is 0 always we don't really care
        return cipher.doFinal(ByteBuffer.allocate(16).putInt(0).array());
    }
    private static byte[] getNonce(long recordId, byte[] seedBytes){
        byte[] nonce = new byte[16];

        try {

            byte[] recordIdBytes = ByteBuffer.allocate(16).putLong(recordId).array();
            nonce = SSEUtil.xorTwoByteArrays(seedBytes, recordIdBytes);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return nonce;
    }

}
