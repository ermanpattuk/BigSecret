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

package edu.utdallas.bigsecret.hash.test;

import static org.junit.Assert.*;

import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Test;

import edu.utdallas.bigsecret.hash.Sha256;

/**
 * Test class for Sha 256 class.
 */
public class TestSha256
{
	public static void printArray(byte[] arr)
	{
		for(int a = 0; a<arr.length; a++)
			System.out.print(arr[a] + " ");
		System.out.println();
	}
	
	@Test
	public void testWithoutTrim() 
	{
		byte[] key = Bytes.toBytes("1234566");
		
		try
		{
			Sha256 h = new Sha256(key);
			
			byte[] data = Bytes.toBytes("why do we fall?");
			
			byte[] hash = h.getHash(data);
			printArray(hash);
			
			System.out.println("Size of the digest is: " + h.hashSize());
		}
		catch (Exception e)
		{
			fail("Sha256 without trim test failed.");
			e.printStackTrace();			
		}
	}
	
	@Test
	public void testWithTrim()
	{
		byte[] key = Bytes.toBytes("1234566");
		
		try
		{
			Sha256 h = new Sha256(key, 10);
			
			byte[] data = Bytes.toBytes("what doesn't kill you makes you stranger");
			
			byte[] hash = h.getHash(data);
			printArray(hash);
			
			System.out.println("Size of the digest is: " + h.hashSize());
		}
		catch (Exception e)
		{
			fail("Sha256 with trim test failed.");
			e.printStackTrace();			
		}
	}
}
