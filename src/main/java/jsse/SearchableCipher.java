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

public interface SearchableCipher {

    byte[] encrypt(byte[] plainBytes, long recordID) throws Exception;

    byte[] decrypt(byte[] cipherBytes, long recordID)throws Exception;

    byte[] encrypt(byte[] plainBytes) throws Exception;

    byte[] decrypt(byte[] cipherBytes)throws Exception;

    byte[] getTrapDoor(byte[] plainBytes) throws Exception;

    public boolean isMatch(byte[] trapDoorBytes, byte[] cipherBytes)throws Exception;
}
