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

package edu.utdallas.bigsecret.util;


/**
 * This class includes some commonly used functions in the workspace.
 */
public class Utilities 
{
	/**
	 * Given an array of bytes, returns the corresponding long value. If the size of the array<br>
	 * is less than 8 bytes, then the result is calculated after 0'ing the input from the left.<br>
	 * For instance:<br>
	 * Input: b0 b1 b2 b3<br>
	 * Output: long conversion for 0 0 0 0 b0 b1 b2 b3<br>
	 * <br>
	 * If the input has more than 8 bytes, than the first 8 bytes are taken.<br>
	 * For instance:<br>
	 * Input: b0 b1 b2 b3 b4 b5 b6 b7 b8 b9<br>
	 * Output: long conversion for b0 b1 b2 b3 b4 b5 b6 b7 b8
	 * @param array Input array of bytes
	 * @return Long value for the input array
	 */
	public static long getLong(byte[] array)
	{
		//either go until the end of input array or at most 8 bytes
		int currentPosition;
		if(array.length < 8)
			currentPosition = array.length - 1;
		else
			currentPosition = 7;
		
		//calculate result
		long result = 0;
		int offset = 0;
		for(; currentPosition>-1; currentPosition--)
		{
			result |= ((long)(array[currentPosition] & 0xff) << offset);
			offset += 8;
		}
		
		return result;
	}
	
	
	/**
	 * Given an array of bytes, increment the value by one. Index 0 <br>
	 * is the most significant bit.
	 * @param input Input array of bytes.
	 * @return Incremented array of bytes. Size may increase.
	 */
	public static byte[] incByteArray(byte[] input)
	{
		byte[] resultArr;
		
		boolean all254 = true;
		for(int a = 0; a<input.length; a++)
		{
			if(input[a] != -1)
			{
				all254 = false;
				break;
			}				
		}
		
		if(all254)
		{
			resultArr = new byte[input.length + 1];
			for(int a = 0; a<resultArr.length; a++)
				resultArr[a] = 0;
			resultArr[0] = 1;	
			
			return resultArr;
		}
		else
		{
			resultArr = new byte[input.length];
			for(int a = 0; a<input.length; a++)
				resultArr[a] = input[a];
			
			for(int a = resultArr.length-1; a>= 0; a--)
			{
				if(resultArr[a] == -1)
				{
					resultArr[a] = 0;
				}
				else 
				{
					resultArr[a]++;
					break;
				}
			}
			
			return resultArr;
		}		
	}
}
