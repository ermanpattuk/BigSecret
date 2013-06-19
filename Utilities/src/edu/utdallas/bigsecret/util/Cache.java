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
import java.util.LinkedList;
import java.util.Queue;


/**
 * Bucketizer instances may need a lot of communication, since they need a bucketValue<br>
 * for a specific bucketId. To reduce this, we implemented this class as an intermediate cache.<br>
 * To limit number of values hold in this cache, a value can be given in the constructed.<br>
 * Two data structures are utilized in this class. First we use a FIFO queue due to limited cache<br>
 * size. Secondly, we use hash map to get data for a specific pair.
 */
public class Cache 
{
	/**
	 * Hash map instance to hold values for a bucketId-bucketValue pair.
	 */
	protected HashMap<ByteArray, ByteArray> m_hashmap;
	
	/**
	 * FIFO queue for the incoming bucketId queries.
	 */
	protected Queue<ByteArray> m_queue;
	
	/**
	 * Number of elements that the cache holds
	 */
	protected int m_cacheSize;
	
	
	/**
	 * Default constructor. Size of cache is 64K.
	 */
	public Cache()
	{
		this(1024*64);
	}
	
	
	/**
	 * Constructor with cache size parameter.
	 * @param cacheSize Number of elements that cache holds.
	 */
	public Cache(int cacheSize)
	{
		m_cacheSize = cacheSize;
		m_hashmap = new HashMap<ByteArray, ByteArray>(m_cacheSize);
		m_queue = new LinkedList<ByteArray>();
	}
	
	
	/**
	 * Returns the size of the cache.
	 * @return Size of the cache.
	 */
	public int getSize()
	{
		return m_cacheSize;
	}
	
	
	/**
	 * Get a bucketValue for a bucketId
	 * @param input BucketId
	 * @return BucketValue for the corresponding BucketId, if it exists.<br>
	 * Returns null otherwise.
	 */
	public byte[] get(byte[] input)
	{
		ByteArray temp = new ByteArray(input);
		
		ByteArray result = m_hashmap.get(temp);
		if(result == null)
		{
			return null;
		}
		else
		{
			return result.getData();
		}
	}
	
	
	/**
	 * Puts a bucketId-bucketValue pair to the cache.<br>
	 * If the cache is full, removes the oldest pair, and puts this new input.
	 * @param key BucketId
	 * @param data BucketValue
	 */
	public void put(byte[] key, byte[] data)
	{
		ByteArray tempKey = new ByteArray(key);
		ByteArray tempData = new ByteArray(data);
		
		if(m_hashmap.containsKey(tempKey))
		{
			m_hashmap.put(tempKey, tempData);
		}
		else
		{
			if(m_queue.size() == m_cacheSize)
			{
				ByteArray removedItem = m_queue.poll();
				
				if(removedItem != null)
				{
					m_hashmap.remove(removedItem);
				}
			}
			
			m_hashmap.put(tempKey, tempData);
			m_queue.add(tempKey);
		}
	}
}