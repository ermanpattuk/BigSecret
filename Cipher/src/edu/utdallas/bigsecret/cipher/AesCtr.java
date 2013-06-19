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

import java.math.BigInteger;
import java.security.SecureRandom;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.lang.ArrayUtils;

/**
 * This class extends abstract Cipher class. It implements AES in counter mode.
 */
public class AesCtr extends JavaxCipher
{
	/**
	 * Secure random generator.
	 */
	protected SecureRandom m_secureRandom;
	
	/**
	 * Number of bytes in a block, which is constant for AES.
	 */
	protected static int BLOCK_SIZE_BYTES = 16;
	
	/**
	 * Number of bits in a block, which is constant for AES.
	 */
	protected static int BLOCK_SIZE_BITS = 128;
	
	/**
	 * Number of bytes in key.
	 */
	protected int KEY_SIZE_BYTES;
	
	
	/**
	 * Class constructor. Creates a Javax.Crypto.Cipher instance with AES in CTR<br>
	 * mode, without any padding. 
	 * @param key Input key for the cipher. Should be 16, 24, or 32 bytes long
	 * @throws Exception Throws exception if key length is not 16, 24, or 32 bytes.<br>
	 * 					 May throw exception based on Javax.Crypto classes.
	 */
	public AesCtr(byte[] key) throws Exception
	{
		//use default constructor for cipher.Cipher
		super();
		
		//check if input key is ok
		if(key.length != 16 && key.length != 24 && key.length != 32)
		{
			throw new Exception("Key length should be 16, 24, or 32 bytes long");
		}
		
		//set key length
		KEY_SIZE_BYTES = key.length;
		
		//create secret key spec instance
		m_keySpec = new SecretKeySpec(key, "AES");
		
		//create cipher instance
		m_cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding");
		
		//create secure random number generator instance
		m_secureRandom = new SecureRandom();
	}

	
	/**
	 * Encrypts input data with AES CTR mode.
	 * @param data Input byte array.
	 * @return Encryption result.
	 * @throws Exception Throws exception if there is no data to encrypt.<br>
	 * 					 May throw exception based on Javax.Crypto.Cipher class
	 */
	public byte[] encrypt(byte[] data) throws Exception 
	{
		//check if there is data to encrypt
		if(data.length == 0)
		{
			throw new Exception("No data to encrypt");
		}
		
		//create iv
		byte[] iv = new byte[BLOCK_SIZE_BYTES];
		byte[] randomNumber = (new BigInteger(BLOCK_SIZE_BITS, m_secureRandom)).toByteArray();
		int a;
		for(a = 0; a<randomNumber.length && a<BLOCK_SIZE_BYTES; a++)
			iv[a] = randomNumber[a];
		for(; a<BLOCK_SIZE_BYTES; a++)
			iv[a] = 0;
		
		//init cipher instance
		m_cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, m_keySpec, new IvParameterSpec(iv));

		//return concatenation of iv + encrypted data		
		return ArrayUtils.addAll(iv, m_cipher.doFinal(data));
	}

	
	/**
	 * Decrypts input data with AES CTR mode
	 * @param data Input byte array.
	 * @return Decryption result.
	 * @throws Exception Throws exception if there is no data to decrypt.<br>
	 * 					 May throw exception based on Javax.Crypto.Cipher class.
	 */
	public byte[] decrypt(byte[] data) throws Exception 
	{
		//call overriden function with offset = 0
		return decrypt(data, 0);
	}

	
	/**
	 * Decrypts input data starting and including the offset index position<br>
	 * with AES CTR mode.
	 * @param data Input byte array.
	 * @param offset Offset to start decryption.
	 * @return Decryption result.
	 * @throws Exception Throws exception if there is no data to decrypt.<br>
	 * 					 Throws exception if offset is invalid.<br>
	 * 					 May throw exception based on Javax.Crypto.Cipher class.
	 */
	public byte[] decrypt(byte[] data, int offset) throws Exception 
	{
		//check if there is data to decrypt after the offset and iv
		if(data.length <= BLOCK_SIZE_BYTES + offset)
		{
			throw new Exception("No data to decrypt");
		}
		
		//get iv value from the beggining of data
		byte[] iv = new byte[BLOCK_SIZE_BYTES];
		System.arraycopy(data, offset, iv, 0, BLOCK_SIZE_BYTES);
		
		//init cipher instance
		m_cipher.init(javax.crypto.Cipher.DECRYPT_MODE, m_keySpec, new IvParameterSpec(iv));
		
		//return decrypted value
		return m_cipher.doFinal(data, (BLOCK_SIZE_BYTES + offset), data.length - (BLOCK_SIZE_BYTES + offset));
	}
}
