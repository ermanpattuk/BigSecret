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


/**
 * This class is created for just ease of use, in the implementation of proxy mode 3.<br>
 * Family values are given a constant value. This is class is created to give a constant<br>
 * , just 0, to family part. No other purpose.
 */
public class NullCipher extends Cipher
{
	/**
	 * Default constructor. Does nothing.
	 * @throws Exception
	 */
	public NullCipher() throws Exception
	{
	}


	/**
	 * Returns a constant value no matter what the input is.<br>
	 * A constant byte array consisting of just a value of 0.
	 * @param data Input byte array. Is not used.
	 * @return A byte array with length 1, and value 0.
	 */
	public byte[] encrypt(byte[] data) throws Exception 
	{
		byte[] result = new byte[1];
		result[0] = 0;
		
		return result;
	}

	
	/**
	 * Is not used.
	 * @param data Input byte array. Is not used.
	 * @return Always returns null.
	 */
	public byte[] decrypt(byte[] data) throws Exception 
	{
		return null;
	}

	
	/**
	 * Is not used.
	 * @param data Input byte array. Is not used.
	 * @param offset Offset to start decryption. Is not used.
	 * @return Always returns null.
	 */
	public byte[] decrypt(byte[] data, int offset) throws Exception 
	{
		return null;
	}
}
