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

import java.util.Arrays;

/**
 * This class is a wrapper for byte[].
 */
public class ByteArray implements Comparable<ByteArray>
{
	/**
	 * byte array data that this instance holds
	 */
	protected byte[] m_data;
	
	
	/**
	 * Class constructor
	 * @param data input data
	 */
	public ByteArray(byte[] data)
	{
		m_data = data;
	}
	
	
	/**
	 * Setter for m_data
	 * @param data input data
	 */
	public void setData(byte[] data)
	{
		m_data = data;
	}
	
	
	/**
	 * Getter for m_data
	 * @return m_data
	 */
	public byte[] getData()
	{
		return m_data;
	}
	
	
	/**
	 * Equals function for ByteArray class.
	 * @param Object that we compare with this ByteArray instance.
	 * @return Returns true if the object is a ByteArray instance, and <br>
	 * byte array data is equal to this ByteArray's data.
	 */
	public boolean equals(Object o)
	{
		byte[] rhsData = ((ByteArray)o).getData();
		
		if(m_data == null || rhsData == null)
			return false;
		
		if(o instanceof ByteArray)
		{
			return Arrays.equals(m_data, ((ByteArray)o).getData());
		}
		else
		{
			return false;			
		}
	}
	
	
	/**
	 * Compares the numerical values of two bytes. 
	 * @param lhs First byte
	 * @param rhs Second byte
	 * @return Returns 1 if first byte is bigger than the second. <br>
	 * Returns 0 if two bytes are equal <br>
	 * Return -1 if the second byte is bigger.
	 */
	private int compareBytes(byte lhs, byte rhs)
	{		
		if(lhs == rhs)
			return 0;
		
		if(lhs >= 0 && rhs < 0)
		{
			return -1;
		}			
		else if(lhs < 0 && rhs >= 0)
		{
			return 1;
		}
		else
		{
			if(lhs < rhs)
				return -1;
			else
				return 1;
		}
	}
	
	
	/**
	 * Calculates hash code.
	 */
	public int hashCode()
	{
		return Arrays.hashCode(m_data);
	}


	/**
	 * Compares two ByteArray instances for their data.
	 * @param r ByteArray instance that is compared
	 * @return Returns 0 if both instances have the same data.<br>
	 * Returns 1 if this instance is bigger.<br>
	 * Returns -1 if input instance is bigger.
	 */
	public int compareTo(ByteArray r)
	{
		if(this.equals(r))
			return 0;
		
		byte[] rhs = r.getData();
		
		boolean leftIsBigger;
		int minLength;
		if(m_data.length > rhs.length)
		{
			leftIsBigger = true;
			minLength = rhs.length;
		}
		else
		{
			leftIsBigger = false;
			minLength = m_data.length;
		}
		
		for(int a = 0; a<minLength; a++)
		{
			int res = compareBytes(m_data[a], rhs[a]);
			
			if(res != 0)
				return res;
		}
		
		if(leftIsBigger)
			return 1;
		else
			return -1;
	}
}
