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
 * Abstract class to perform encryption, decryption, and decryption by an offset.
 */
public abstract class Cipher 
{	
	/**
	 * Default constructor.
	 * @throws Exception
	 */
	public Cipher() throws Exception
	{		
	}
	
	
	/**
	 * Encrypt input data.
	 * @param data Input data.
	 * @return Encryption result.
	 * @throws Exception
	 */
	public abstract byte[] encrypt(byte[] data) throws Exception;
	
	
	/**
	 * Decrypt input data.
	 * @param data Input data.
	 * @return Decryption result.
	 * @throws Exception
	 */
	public abstract byte[] decrypt(byte[] data) throws Exception;
	
	
	/**
	 * Decrypt input data starting from index offset.
	 * @param data Input data.
	 * @param offset Starting index for decryption.
	 * @return Decryption result.
	 * @throws Exception
	 */
	public abstract byte[] decrypt(byte[] data, int offset) throws Exception;
}
