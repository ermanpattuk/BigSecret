/**
* Copyright (c) 2013 The University of Texas at Dallas, Data Security and Privacy Lab. 
* All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not use this 
* file except in compliance with the License. You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software distributed 
* under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR 
* CONDITIONS OF ANY KIND, either express or implied. See the License for the specific 
* language governing permissions and limitations under the License. See accompanying
* LICENSE file.
*/

package edu.utdallas.bigsecret.cipher;

import javax.crypto.spec.SecretKeySpec;

/**
 * This class extends Cipher. This class functions as Electronic Code Book mode for AES
 */
public class AesEcb extends JavaxCipher
{
	/**
	 * Number of bytes for key
	 */
	protected int KEY_SIZE_BYTES;

	
	/**
	 * Constructor for this class. It instantiates a javax crypto class <br>
	 * instance, in AES ECB mode and PKCS5 Padding.
	 * @param key Secret key for the cipher. Should be 16, 24 or 32 bytes long
	 * @throws Exception Throws exception if key length is not 16, 24, or 32 bytes long. 
	 */
	public AesEcb(byte[] key) throws Exception 
	{
		//call constructor of super class
		super();
	
		//check input key
		if(key == null || (key.length != 16 && key.length != 24 && key.length != 32))
		{
			throw new Exception("Key length should be 16, 24, or 32 bytes long");
		}
		
		//assign key length
		KEY_SIZE_BYTES = key.length;
		
		//init key spec instance
		m_keySpec = new SecretKeySpec(key, "AES");
		
		//init cipher instance
		m_cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
	}

	
	/**
	 * Encrypts input data with AES ECB mode.
	 * @param data Input byte array.
	 * @return Encryption result.
	 * @throws Exception Throws exception if there is no data to encrypt.<br>
	 * 					 May throw exception based on Javax.Crypto.Cipher class
	 */
	public byte[] encrypt(byte[] data) throws Exception 
	{
		//check if there is data to encrypt
		if(data == null || data.length == 0)
		{
			throw new Exception("No data to encrypt");
		}
		
		//init cipher instance
		m_cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, m_keySpec);
		
		//return encrypted data
		return m_cipher.doFinal(data);
	}

	
	/**
	 * Decrypts input data with AES ECB mode
	 * @param data Input byte array.
	 * @return Decryption result.
	 * @throws Exception Throws exception if there is no data to decrypt.<br>
	 * 					 May throw exception based on Javax.Crypto.Cipher class.
	 */
	public byte[] decrypt(byte[] data) throws Exception 
	{
		//call overloaded function with offset = 0
		return decrypt(data, 0);
	}

	
	/**
	 * Decrypts input data starting and including the offset index position<br>
	 * with AES ECB mode.
	 * @param data Input byte array.
	 * @param offset Offset to start decryption.
	 * @return Decryption result.
	 * @throws Exception Throws exception if there is no data to decrypt.<br>
	 * 					 Throws exception if offset is invalid.<br>
	 * 					 May throw exception based on Javax.Crypto.Cipher class.
	 */
	public byte[] decrypt(byte[] data, int offset) throws Exception 
	{
		//check if there is data to decrypt after the offset
		if(data == null || data.length == 0 || data.length <= offset)
		{
			throw new Exception("No data to decrypt");
		}
		
		//init cipher instance
		m_cipher.init(javax.crypto.Cipher.DECRYPT_MODE, m_keySpec);
		
		//return decrypted result
		return m_cipher.doFinal(data, offset, data.length - offset);
	}
}
