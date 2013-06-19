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

/**
 * This is an abstract class that contains functions for a hash function.
 */
public abstract class Hasher 
{	
	/**
	 * Class constructor.
	 * @throws Exception
	 */
	public Hasher() throws Exception
	{
	}
	
	
	/**
	 * Calculate hash for the input data.
	 * @param data Input data.
	 * @return Hash value of data if data is not null. null otherwise.
	 * @throws Exception
	 */
	public abstract byte[] getHash(byte[] data) throws Exception;
	
	
	/**
	 * Return size of a hash value.
	 * @return Size of the hash value.
	 */
	public abstract int hashSize();
}
