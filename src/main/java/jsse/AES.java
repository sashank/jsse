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
import java.security.InvalidParameterException;


public class AES implements BlockCipher {

    protected Cipher cipher;
    protected SecretKeySpec keySpec ;
    byte[]  ivBytes = null;

    public AES(String mode, SecretKeySpec spec) throws InvalidParameterException {
        try {
            keySpec = spec ;
            cipher = Cipher.getInstance(mode, "BC");
        } catch (Exception e){
            throw  new InvalidParameterException("Invalid Parameters" + e.getMessage());
        }

    }
    public AES(String mode, SecretKeySpec spec, byte[] ivBytes) throws InvalidParameterException{
        try {
            keySpec = spec ;
            this.ivBytes = ivBytes;
            cipher = Cipher.getInstance(mode, "BC");
        } catch (Exception e){
            throw  new InvalidParameterException("Invalid Parameters" + e.getMessage());
        }
    }
    public AES(String mode, byte[] key) throws InvalidParameterException {
            byte[] fullKey = new byte[16];

            if(key == null )
                throw new InvalidParameterException("Key is empty cannot proceed" );
            if(key.length > 16)
                throw new InvalidParameterException("Key Size > 16 bytes" + key.length);

            System.arraycopy(key,0,fullKey,0,key.length);
            if(key.length < 16){
               for (int i = key.length ; i < 16 ; i ++)
                   fullKey[i] = 0 ;
            }

            try {
                keySpec = new SecretKeySpec(fullKey, "AES");
                cipher = Cipher.getInstance(mode, "BC");
            }   catch (Exception e){
                 throw  new InvalidParameterException("Invalid Parameters" + e.getMessage());
            }

    }

    public  byte[] encrypt(byte[] plainBytes) throws Exception {

        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
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
