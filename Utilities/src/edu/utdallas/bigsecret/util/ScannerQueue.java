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

import java.util.HashMap;
import java.util.Map;
import java.util.PriorityQueue;
import java.util.Set;
import java.util.TreeSet;


/**
 * When a Scan query is performed over model-2 data, BigSecret needs<br>
 * to give rows in sorted order to the client. Each plain row-key may have<br>
 * multiple encrypted versions, since AES CTR is used. Thus, we need to hold<br>
 * what encrypted values correspond to which plain row.<br>
 * We use a mapping to perform update and retrieve operations fast. <br>
 * To sort the rows, we use a heap structure.
 */
public class ScannerQueue 
{
	/**
	 * Heap to hold row key's ordering	
	 */
	private PriorityQueue<ByteArray> m_pq;
	
	/**
	 * Hash map for the row-data mapping.
	 */
	private Map<ByteArray, Set<ByteArray>> m_map;
	
	
	/**
	 * Default constructor.
	 */
	public ScannerQueue()
	{
		m_pq = new PriorityQueue<ByteArray>();
		
		m_map = new HashMap<ByteArray, Set<ByteArray>>();
	}
	
	
	/**
	 * Put a Plain-Encrypted row pair.
	 * @param plainRow Byte array for the plain row key
	 * @param encRow Byte array for the encrypted row key
	 */
	public void put(byte[] plainRow, byte[] encRow)
	{
		put(new ByteArray(plainRow), new ByteArray(encRow));
	}
	
	
	/**
	 * Put a Plain-Encrypted row pair.
	 * @param plainRow ByteArray for the plain row key
	 * @param encRow ByteArray for the encrypted row key
	 */
	public void put(ByteArray plainRow, ByteArray encRow)
	{
		if(m_map.containsKey(plainRow))
		{
			Set<ByteArray> set = m_map.get(plainRow);
			set.add(encRow);
			
			m_map.put(plainRow, set);
		}
		else
		{
			m_pq.add(plainRow);
			
			Set<ByteArray> set = new TreeSet<ByteArray>();
			set.add(encRow);
			
			m_map.put(plainRow, set);
		}
	}
	
	
	/**
	 * Get the first plain row key's encrypted values.
	 * @return A set of encrypted row key's.
	 */
	public Set<ByteArray> get()
	{
		ByteArray nextItem = m_pq.remove();
		
		return m_map.remove(nextItem);
	}
	
	
	/**
	 * Get the number of plain row key's in the heap.
	 * @return Number of plain row key's in the heap.
	 */
	public int size()
	{
		return m_pq.size();
	}
}
