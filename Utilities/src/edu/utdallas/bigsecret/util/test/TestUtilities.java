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

package edu.utdallas.bigsecret.util.test;

import static org.junit.Assert.*;

import org.junit.Test;

import edu.utdallas.bigsecret.util.Utilities;


/**
 * Test class for Utilities project.
 */
public class TestUtilities 
{
	public static void printArray(byte[] arr)
	{
		for(int a = 0; a<arr.length; a++)
			System.out.print(arr[a] + " ");
		System.out.println();
	}
		
	@Test
	public void testGetLong() 
	{
		byte[] input = new byte[2];
		input[0] = 1;
		input[1] = 3;
		
		long functionOutput = Utilities.getLong(input);
		
		if(functionOutput != 259)
		{
			System.out.println("Calculated long value: " + functionOutput);
			fail("Utilities getLong test failed.");
		}		
	}
	
	@Test
	public void testIncrement()
	{
		byte[] input = new byte[2];
		input[0] = 1;
		input[1] = 3;
		
		byte[] incremented = Utilities.incByteArray(input);
		
		if(incremented.length != 2 || incremented[0] != 1 || incremented[1] != 4)
		{
			fail("Utilities increment test failed.");			
		}
	}
}
