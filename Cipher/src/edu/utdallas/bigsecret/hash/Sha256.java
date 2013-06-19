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

package edu.utdallas.bigsecret.hash;

import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class extends abstract class Hasher. It implements Sha 256. By <br>
 * default, the output size is 256 bits. Moreover, a trim can be performed <br>
 * by assigning the number of bytes that are extracted from the hash value <br>
 * is given. In that case, the last trim_value bytes are returned as the digest.
 */
public class Sha256 extends JavaxHasher
{
	/**
	 * Number of bytes returned. If 0, that means return all digest.
	 */
	protected int m_trimCount;
	
	
	/**
	 * Constructor for the class that does not trim the output.
	 * @param key Secret key for the hash function.
	 * @throws Exception Throws exception if the key is null, or empty.					
	 */
	public Sha256(byte[] key) throws Exception
	{
		this(key, 0);
	}
	
	/**
	 * Class constructor that trims the output.
	 * @param key Secret key for the hash function.
	 * @param trimCount Number of bytes of the output.
	 * @throws Exception Throws exception if the key is null, or empty.<br> 
	 * 					 Throws exception if the trim value is invalid.
	 */
	public Sha256(byte[] key, int trimCount) throws Exception
	{
		//check key value
		if(key == null || key.length == 0)
			throw new Exception("Key is null or has no data");
		
		//set key instance
		m_keySpec = new SecretKeySpec(key, "HmacSHA256");
		
		//init mac object
		m_mac = Mac.getInstance("HmacSHA256");
		m_mac.init(m_keySpec);
		
		if(0 < trimCount && trimCount < m_mac.getMacLength())
		{
			m_trimCount = trimCount;
		}			
		else
		{
			m_trimCount = 0;
		}
	}

	
	/**
	 * Calculates hash result for the input data.
	 * @param data Input byte array.
	 * @return Digest of the input.
	 * @throws May throw exception based on Javax.Crypto class
	 */
	public byte[] getHash(byte[] data) throws Exception 
	{
		if(m_trimCount == 0)
			return m_mac.doFinal(data);
		else
			return Arrays.copyOf(m_mac.doFinal(data), m_trimCount);
	}

	
	/**
	 * Returns the number of bytes of this hasher's digest.<br>
	 * If the output is not trimmed, returns 32. Otherwise returns trimsize.
	 * @return Returns 32 without trim, otherwise returns trimsize.
	 */
	public int hashSize() 
	{
		if(m_trimCount == 0)
			return m_mac.getMacLength();
		else
			return m_trimCount;
	}
}
