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
 * This class extends abstract class Hasher. Subclasses of this abstract class uses Javax.Crypto library.
 */
public abstract class JavaxHasher extends Hasher
{
	/**
	 * SecretKeySpec instance that holds key
	 */
	protected javax.crypto.spec.SecretKeySpec m_keySpec;
	
	/**
	 * Mac instance
	 */
	protected javax.crypto.Mac m_mac;
	
	/**
	 * Class constructor
	 * @throws Exception
	 */
	public JavaxHasher() throws Exception
	{
		
	}
}
