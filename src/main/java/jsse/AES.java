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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * Created by sashank dara on 05/09/14.
 */
public class AES implements BlockCipher {

    protected Cipher cipher;
    protected SecretKeySpec keySpec ;
    byte[]  ivBytes = null;

    public AES(String mode, SecretKeySpec spec) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
            keySpec = spec ;
            cipher = Cipher.getInstance(mode, "BC");
    }
    public AES(String mode, SecretKeySpec spec, byte[] ivBytes) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
            keySpec = spec ;
            this.ivBytes = ivBytes;
            cipher = Cipher.getInstance(mode, "BC");
    }
    public AES(String mode, byte[] key) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
            byte[] fullKey = new byte[16];
            System.arraycopy(key,0,fullKey,0,key.length);
            if(key.length < 16){
               for (int i = key.length ; i < 16 ; i ++)
                   fullKey[i] = 0 ;
            }

            keySpec = new SecretKeySpec(fullKey,"AES");
            cipher = Cipher.getInstance(mode, "BC");
    }

    public  byte[] encrypt(byte[] plainBytes) throws Exception {

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        //encrypt the message
        return cipher.doFinal(plainBytes);
    }


    public  byte[] decrypt(byte[] cipherText) throws Exception {

        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        return cipher.doFinal(cipherText);
    }

    public byte[] getIvBytes(long id){
        byte[] idBytes = ByteBuffer.allocate(16).putLong(id).array();
        return SSEUtil.xorTwoByteArrays(ivBytes, idBytes);
    }

    public byte[] encrypt(byte[] plainBytes, byte[] ivBytes) throws Exception {

        cipher.init(Cipher.ENCRYPT_MODE, keySpec,new IvParameterSpec(ivBytes) );

        return cipher.doFinal(plainBytes);
    }

    public byte[] decrypt(byte[] cipherBytes, byte[] ivBytes) throws Exception {

        cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(ivBytes));

        return cipher.doFinal(cipherBytes);
    }

}
