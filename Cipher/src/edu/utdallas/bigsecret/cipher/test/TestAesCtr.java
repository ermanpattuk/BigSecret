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

package edu.utdallas.bigsecret.cipher.test;

import static org.junit.Assert.*;

import java.util.Arrays;

import org.apache.commons.lang.ArrayUtils;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Test;

import edu.utdallas.bigsecret.cipher.AesCtr;


/**
 * Test class for Aes Ctr class.
 */
public class TestAesCtr 
{
	public static void printArray(byte[] arr)
	{
		for(int a = 0; a<arr.length; a++)
			System.out.print(arr[a] + " ");
		System.out.println();
	}
	
	@Test
	public void testDecryptByteArray() 
	{
		byte[] key = Bytes.toBytes("1234567890123456");
		
		try 
		{
			AesCtr cip = new AesCtr(key);
						
			byte[] originalData = Bytes.toBytes("Do you think it's air that you breath?");
			
			System.out.println("Original Data: ");
			printArray(originalData);
			
			byte[] encData = cip.encrypt(originalData);
			
			System.out.println("Encrypted Data: ");
			printArray(encData);
			
			byte[] decData = cip.decrypt(encData);
			
			System.out.println("Decrypted Data: ");
			printArray(decData);
			
			if(! Arrays.equals(originalData, decData))
			{
				fail("AesCtr encryption decryption mechanism failed. Data changes after encryption and decryption!!");
			}
		} 
		catch (Exception e) 
		{
			fail("AesCtr encrypt test failed.");
			e.printStackTrace();
		}	
	}

	@Test
	public void testDecryptByteArrayInt() 
	{
		byte[] key = Bytes.toBytes("1234567890123456");
		
		try 
		{
			AesCtr cip = new AesCtr(key);
						
			byte[] originalData = Bytes.toBytes("He is the one.");
			
			System.out.println("Original Data: ");
			printArray(originalData);
			
			byte[] encData = cip.encrypt(originalData);
			
			System.out.println("Encrypted Data: ");
			printArray(encData);
			
			byte[] pad = new byte[2];
			pad[0] = 1;
			pad[1] = 0;
			
			byte[] padded = ArrayUtils.addAll(pad, encData);
			
			byte[] decData = cip.decrypt(padded, 2);
			
			System.out.println("Decrypted Data: ");
			printArray(decData);
			
			if(! Arrays.equals(originalData, decData))
			{
				fail("AesCtr encryption decryption mechanism failed. Data changes after encryption and decryption!!");
			}
		} 
		catch (Exception e) 
		{
			fail("AesCtr encrypt test failed.");
			e.printStackTrace();
		}
	}

}
