/*
*
*    jsse is Symmetric Searchable Encryption Library in Java
*
*    jsse is developed by Sashank Dara (sashank.dara@gmail.com)
*
*    WBDD  is a searchable symmetric encryption technique
*    developed by  Brent R Waters and  Dirk Balfanz, and  Glenn  Durfee,and  Diana K Smetters
*
*    Reference: SWaters, Brent R., et al. "Building an Encrypted and Searchable Audit Log." NDSS. Vol. 4. 2004.
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

package jsse;

import com.cisco.fnr.FNR;

import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidParameterException;
import java.util.Arrays;


public class WDDS implements SearchableCipher {

    private AES aesCipher, aesRndCipher = null;
    private FNR fnrCipher, fnrRndCipher = null;
    private String type;
    public static int BLOCK_SIZE;
    public static int BLOCK_BYTES;
    public static final  String FLAG = "CAPTURE-THE-FLAG" ; //Ensure it is 16 letters i.e 16 bytes
    public static final  String SMALL_FLAG = "FLAG" ; //Ensure it is 16 letters i.e 16 bytes
    private byte[] randomBytes;

    public WDDS(SecretKeySpec spec,String type, int blockSize,byte[] randBytes) throws InvalidParameterException{

        switch (type){
            case "AES" :
                if(blockSize != 128)
                    throw new InvalidParameterException("Invalid Block Size for AES");
                aesCipher = new AES("AES/ECB/PKCS7Padding", spec);

                break;
            case "FNR" :
                fnrCipher = new FNR(spec.getEncoded(),"tweak",blockSize);
                break;
            default:
                throw  new InvalidParameterException("Invalid Block Cipher type");
        }

        // init parameters
        this.type = type ;
        BLOCK_SIZE  = blockSize;
        BLOCK_BYTES = BLOCK_SIZE/Byte.SIZE;
        randomBytes = randBytes;
    }


    public byte[] getTrapDoor(byte[] plainBytes) throws Exception {
        if (plainBytes == null)
            return new byte[0];

        byte[] bBytes = getBBytes(plainBytes);

        return SSEUtil.xorTwoByteArrays(bBytes, FLAG.getBytes());
    }

    public byte[] getBBytes(byte[] plainBytes) throws Exception {
        byte[] aBytes  = encrypt(plainBytes);
        aesRndCipher = new AES("AES/ECB/NoPadding", aBytes); // Note: a_bytes is the key
        return aesRndCipher.encrypt(randomBytes);
    }

	/*
	 * Blind folded Match !
	 */

    public boolean isMatch(byte[] trapDoorBytes, byte[] bBytes)
            throws Exception {

        if(bBytes == null || trapDoorBytes == null)
            return false;

        byte[] flagBytes = SSEUtil.xorTwoByteArrays(trapDoorBytes,bBytes);

        return  Arrays.equals(flagBytes, FLAG.getBytes()) ;

    }

    public byte[] encrypt(byte[] plainBytes) throws Exception {
        switch (type){
            case "AES" :
                return aesCipher.encrypt(plainBytes);
            case "FNR" :
                return fnrCipher.encrypt(plainBytes);
        }
        return null;
    }

    public byte[] decrypt(byte[] cipherBytes) throws Exception {
        switch (type){
            case "AES" :
                return aesCipher.decrypt(cipherBytes);
            case "FNR" :
                return fnrCipher.decrypt(cipherBytes);
        }
        return null;
    }

}

