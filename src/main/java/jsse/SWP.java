/*
*
*    jsse is Symmetric Searchable Encryption Library in Java
*
*    jsse is developed by Sashank Dara (sashank.dara@gmail.com)
*
*    SWP is a popular searchable symmetric encryption technique
*    developed by Song, Wagner and Perrig
*
*    Reference: Song, Dawn Xiaoding, David Wagner, and Adrian Perrig. "Practical techniques for searches on encrypted data."
*    Security and Privacy, 2000. S&P 2000. Proceedings. 2000 IEEE Symposium on. IEEE, 2000.
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


public class SWP implements SearchableCipher {

    private AES aesCipher, aesTmpCipher = null;
    private FNR fnrCipher, fnrTmpCipher = null;
    private String type;
    public static int BLOCK_SIZE;
    public static int BLOCK_BYTES;
    private byte[] seedBytes;


    private final int left;
    private final int right ;

    public SWP(SecretKeySpec spec, String type, double loadFactor, int blockSize) throws InvalidParameterException{

        if( loadFactor <= 0 || loadFactor > 1)
            throw new InvalidParameterException("Invalid Load Factor");

        StreamCipher.init(spec);
        seedBytes = SSEUtil.getRandomBytes(16); // For Nonce
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
        this.left =  ((int) (loadFactor  * BLOCK_BYTES));
        this.right = BLOCK_BYTES - left ;
    }

    public byte[] encrypt(byte[] plainBytes, long recordID) throws Exception {

        if (plainBytes == null)
            return new byte[0];

		/* Generate Stream Cipher Bytes */
        byte[] streamCipherBytes = StreamCipher.getRandomStreamOfBytes(
                recordID, seedBytes);

        byte[] blockCipherBytes = encrypt(plainBytes);

		/* Split the cipher Bytes into {left, Right} */
        byte[] blockCipherBytesLeft = Arrays.copyOfRange(blockCipherBytes, 0,
                left);
        byte[] streamCipherBytesLeft = Arrays.copyOfRange(streamCipherBytes, 0,
                left);

		/* Generate search layer */
        byte[] tmpBytes = getSearchLayer(blockCipherBytesLeft,streamCipherBytesLeft);

        byte[] searchLayerBytesRight;
        if(right == 0) // No false positives but additional storage
          searchLayerBytesRight = Arrays.copyOfRange(tmpBytes, 0, BLOCK_BYTES);
        else  //Expect false positives while searching
          searchLayerBytesRight = Arrays.copyOfRange(tmpBytes,0,right);


        byte[] searchLayerBytes = new byte[streamCipherBytesLeft.length+ searchLayerBytesRight.length];

        System.arraycopy(streamCipherBytesLeft, 0, searchLayerBytes, 0, left);
        System.arraycopy(searchLayerBytesRight, 0, searchLayerBytes, left,
                searchLayerBytesRight.length);

        return SSEUtil.xorTwoByteArrays(blockCipherBytes, searchLayerBytes);
    }

    public byte[] decrypt(byte[] cipherBytes, long recordID) throws Exception {
        if (cipherBytes == null)
            return new byte[0];

		/* Generate a Stream Cipher */
        byte[] streamCipherBytes =
                StreamCipher.getRandomStreamOfBytes(recordID, seedBytes);

        byte[] streamCipherBytesLeft =
                Arrays.copyOfRange(streamCipherBytes, 0, left);


		/* Split the cipher Bytes into {left, Right}  */
        byte[] cipherBytesLeft = Arrays.copyOfRange(cipherBytes, 0,  left);
        byte[] cipherBytesRight = Arrays.copyOfRange(cipherBytes, left, cipherBytes.length);

		/*
		 * Peel off the left bytes of search layer from cipherText to get left
		 * bytes of Block Cipher
		 */

        byte[] blockCipherBytesLeft = SSEUtil.xorTwoByteArrays(cipherBytesLeft,
                streamCipherBytesLeft);

        if(blockCipherBytesLeft.length == BLOCK_BYTES)
            return  decrypt(blockCipherBytesLeft);

        else {

            /*
             * compute the right bytes of search layer
             * */

            byte[] tmpBytes = getSearchLayer(blockCipherBytesLeft,streamCipherBytesLeft);
            byte[] tmpBytesRight = Arrays.copyOfRange(tmpBytes, 0, right);


            byte[] blockCipherBytesRight = SSEUtil.xorTwoByteArrays(
                    cipherBytesRight, tmpBytesRight);

            byte[] blockLayerBytes = new byte[BLOCK_BYTES];
            System.arraycopy(blockCipherBytesLeft, 0, blockLayerBytes, 0, left);
            System.arraycopy(blockCipherBytesRight, 0, blockLayerBytes, left, right);

            return decrypt(blockLayerBytes);
        }
    }

    public byte[] getTrapDoor(byte[] plainBytes) throws Exception {
        return encrypt(plainBytes);
    }

	/*
	 * Blind folded Match !
	 */

    public boolean isMatch(byte[] trapDoorBytes, byte[] cipherBytes)
            throws Exception {

        if(cipherBytes == null || trapDoorBytes == null)
            return false;

        /* Peel off the search layer bytes of given layer */
        byte[] searchBytes = SSEUtil.xorTwoByteArrays(trapDoorBytes, cipherBytes);
        byte[] searchBytesLeft  = Arrays.copyOfRange(searchBytes, 0, left);
        byte[] searchBytesRight = Arrays.copyOfRange(searchBytes,left,cipherBytes.length);


        /* Split the trapDoorBytes into {left, Right} of Left bytes and Right bytes */
        byte[] trapDoorBytesLeft  = Arrays.copyOfRange(trapDoorBytes,0,left);

        /* Verify search layer */
        byte[] tmpBytes = getSearchLayer(trapDoorBytesLeft, searchBytesLeft);
        byte[] tmpBytesRight ;
        if(right == 0)
         tmpBytesRight = Arrays.copyOfRange(tmpBytes,0,BLOCK_BYTES);
        else
          tmpBytesRight = Arrays.copyOfRange(tmpBytes,0,right);

        return  Arrays.equals(searchBytesRight,tmpBytesRight) ;

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

    private byte[] getSearchLayer(byte[] key, byte[] data)  throws Exception {
        switch (type) {
            case "AES" :
                 if(aesTmpCipher == null)
                     aesTmpCipher = new AES("AES/ECB/PKCS7Padding", key);
                return aesTmpCipher.encrypt(data);
            case "FNR" :
                 if(fnrTmpCipher == null)
                     fnrTmpCipher = new FNR(key,"tweak",data.length * Byte.SIZE); //Not Block Size
                return fnrTmpCipher.encrypt(data);
        }
        return  null;
    }

}

