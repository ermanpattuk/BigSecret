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

package edu.utdallas.bigsecret.bucketizer;

import java.security.SecureRandom;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.util.Bytes;

import edu.utdallas.bigsecret.util.Utilities;

/**
 * This class is used to bucketize long values.<br>
 * Number of bucket ids is limited to 2^30. 
 */
public class LongBucketizer extends HBaseBucketizer
{
	/**
	 * Number of buckets in this bucketizer
	 */
	protected int m_numberOfBuckets;
	
	/**
	 * Domain of a partitioned bucket.
	 */
	protected long m_divisor;
		
	/**
	 * Minimum value in the long domain.
	 */
	protected long m_minValue;
		
	/**
	 * Maximum value in the long domain.
	 */
	protected long m_maxValue;
	
	
	/**
	 * Constructor that can be used for creating buckets. This constructor should not be used in Proxy.
	 * @param conf Configuration instance for HBase connection.
	 * @param id Bucketizer ID.
	 * @param minValue Minimum value that will be bucketized.
	 * @param maxValue Maximum value that will be bucketized.
	 * @param numberOfBuckets Number of buckets
	 * @throws Exception Throws exception if min or max values are invalid.<br>
	 * Throws exception number of buckets is invalid.<br>
	 * Throws exception if another bucketizer exists with the given id, but with different info.
	 */
	public LongBucketizer(Configuration conf, String id, long minValue, long maxValue, int numberOfBuckets) throws Exception
	{
		//call super class constructor
		super(id, conf);
		
		//check inputs
		if(minValue >= maxValue)
			throw new Exception("Min value should be smaller than max value");
		else if(numberOfBuckets <= 0)
			throw new Exception("Number of buckets can not be non positive");
		
		//set parameters		
		m_minValue = minValue;
		m_maxValue = maxValue;
		m_numberOfBuckets = numberOfBuckets;
		
		m_divisor = (m_maxValue - m_minValue) / m_numberOfBuckets;
		
		if(doesExist())
		{
			//check if min value is true
			byte[] hdata = getBucketInfoFromHBase(Bytes.toBytes("min"));
			if(hdata == null)
			{
				throw new Exception("min data does not exist for bucketizer id=" + id);
			}
			else
			{
				if(Bytes.toLong(hdata) != m_minValue)
				{
					throw new Exception("Bucketizer info does not match. Different min values");
				}
			}
			
			//check if max value is true
			hdata = getBucketInfoFromHBase(Bytes.toBytes("max"));
			if(hdata == null)
			{
				throw new Exception("max data does not exist for bucketizer id=" + id);
			}
			else
			{
				if(Bytes.toLong(hdata) != m_maxValue)
				{
					throw new Exception("Bucketizer info does not match. Different max values");
				}
			}
			
			//check if divisor value is true
			hdata = getBucketInfoFromHBase(Bytes.toBytes("divisor"));
			if(hdata == null)
			{
				throw new Exception("divisor data does not exist for bucketizer id=" + id);
			}
			else
			{
				if(Bytes.toLong(hdata) != m_divisor)
				{
					throw new Exception("Bucketizer info does not match. Different divisor values");
				}
			}
			
			//check if number of buckets value is true
			hdata = getBucketInfoFromHBase(Bytes.toBytes("buckets"));
			if(hdata == null)
			{
				throw new Exception("buckets data does not exist for bucketizer id=" + id);
			}
			else
			{
				if(Bytes.toInt(hdata) != m_numberOfBuckets)
				{
					throw new Exception("Bucketizer info does not match. Different buckets values");
				}
			}
		}
	}
	
	
	/**
	 * Constructor for use in Proxy.
	 * @param conf Configuration instance for HBase connection.
	 * @param id Bucketizer ID.
	 * @throws Exception Throws exception if a long bucketizer does not exist with the given ID.
	 */
	public LongBucketizer(String id, Configuration conf) throws Exception
	{
		this(id, 1024 * 64, conf);
	}
	
	
	/**
	 * Constructor for use in Proxy.
	 * @param conf Configuration instance for HBase connection.
	 * @param id Bucketizer ID.
	 * @param cacheSize Size of the cache.
	 * @throws Exception Throws exception if a long bucketizer does not exist with the given ID.
	 */
	public LongBucketizer(String id, int cacheSize, Configuration conf) throws Exception
	{
		//call super constructor
		super(id, cacheSize, conf);
		
		if(doesExist())
		{
			//check if min value is true
			byte[] hdata = getBucketInfoFromHBase(Bytes.toBytes("min"));
			if(hdata == null)
			{
				throw new Exception("min data does not exist for bucketizer id=" + id);
			}
			else
			{
				m_minValue = Utilities.getLong(hdata);
			}
			
			//check if max value is true
			hdata = getBucketInfoFromHBase(Bytes.toBytes("max"));
			if(hdata == null)
			{
				throw new Exception("max data does not exist for bucketizer id=" + id);
			}
			else
			{
				m_maxValue = Utilities.getLong(hdata);
			}
			
			//check if divisor value is true
			hdata = getBucketInfoFromHBase(Bytes.toBytes("divisor"));
			if(hdata == null)
			{
				throw new Exception("divisor data does not exist for bucketizer id=" + id);
			}
			else
			{
				m_divisor = Utilities.getLong(hdata);
			}
			
			//check if number of buckets value is true
			hdata = getBucketInfoFromHBase(Bytes.toBytes("buckets"));
			if(hdata == null)
			{
				throw new Exception("buckets data does not exist for bucketizer id=" + id);
			}
			else
			{
				m_numberOfBuckets = Bytes.toInt(hdata);
			}
		}
		else
		{
			throw new Exception("Bucketizer with id=" + id + " does not exist");
		}
	}

	
	@Override
	public byte[] getBucketValue(byte[] input) throws Exception 
	{
		int bucketId = getBucketId(input);
		
		if(bucketId >= m_numberOfBuckets)
			bucketId = m_numberOfBuckets - 1;
		else if(bucketId < 0)
			bucketId = 0;
		
		byte[] result = getBucketValueFromHBase(Bytes.toBytes(bucketId));
		
		return result;
	}
	

	@Override
	public byte[] getNextBucketValue(byte[] input) throws Exception 
	{
		//check input
		if(input == null || input.length == 0)
			throw new Exception("Bucket ID is null or has no data");
		
		//calculate bucket id for this input
		int bucketId = getBucketId(input);
		
		//check if that is the last bucket id
		if(bucketId >= m_numberOfBuckets - 1 || bucketId < 0)
		{
			//if so, return null
			return null;
		}
		else
		{
			//otherwise return next bucket id's value
			return getBucketValueFromHBase(Bytes.toBytes(bucketId + 1));
		}
	}
	

	@Override
	public byte[] getPrevBucketValue(byte[] input) throws Exception 
	{
		//check input
		if(input == null || input.length == 0)
			throw new Exception("Bucket ID is null or has no data");
		
		//calculate bucket id for this input
		int bucketId = getBucketId(input);
		
		//check if that is the first bucket id
		if(bucketId <= 0 || bucketId >= m_numberOfBuckets)
		{
			//if so, return null
			return null;
		}
		else
		{
			//otherwise return prev bucket id's value
			return getBucketValueFromHBase(Bytes.toBytes(bucketId - 1));
		}
	}
	
	
	/**
	 * Given an input, calculate bucket ID. If length of input is smaller then number of <br>
	 * bytes for input, append least significant bits with 0. <br>
	 * If input's size is larger, then get the most significant bytes. Otherwise, return input as is.
	 * @param input Byte array input
	 * @return Bucket ID
	 */
	private int getBucketId(byte[] input) throws Exception
	{
		//check input
		if(input == null || input.length == 0)
			throw new Exception("Input bucket id is null or has no data");
		
		long inputLong = Utilities.getLong(input);
		
		int bucketId = (int)((inputLong - m_minValue)/m_divisor);
		
		return bucketId;
	}
	

	@Override
	public int getBucketValueSize() 
	{
		//size of long
		return 4;
	}
	

	@Override
	public void createBuckets() throws Exception 
	{
		//check if there is already information about this bucketizer
		if(doesExist())
		{
			throw new Exception("Bucketizer already exists");
		}
		
		//put bucketizer info to hbase
		putBucketInfoToHBase(Bytes.toBytes("min"), Bytes.toBytes(m_minValue));
		putBucketInfoToHBase(Bytes.toBytes("max"), Bytes.toBytes(m_maxValue));
		putBucketInfoToHBase(Bytes.toBytes("divisor"), Bytes.toBytes(m_divisor));
		putBucketInfoToHBase(Bytes.toBytes("buckets"), Bytes.toBytes(m_numberOfBuckets));
		
		int bucketId = 0;
		int bucketValue = -1;
		
		int bitDiff = 8;
		
		SecureRandom ranGen = new SecureRandom();
		
		for(; bucketId<m_numberOfBuckets; bucketId++)
		{
			if(bucketId % 10000 == 0)
				System.out.println("Finished number of buckets: " + bucketId);
			
			bucketValue += 1 + ranGen.nextInt(bitDiff);
			putBucketValueToHBase(Bytes.toBytes(bucketId), Bytes.toBytes(bucketValue));
		}
		
		m_tableBucketInfo.flushCommits();
		m_tableBucketMap.flushCommits();
	}
	
	
	/**
	 * Remove this bucketizer's data from the bucket table.
	 */
	public void removeBuckets() throws Exception
	{
		if(doesExist())
		{
			removeBucketInfoFromHBase();
			
			for(int a = 0; a<m_numberOfBuckets; a++)
				removeBucketValueFromHBase(Bytes.toBytes(a));
		}
	}
}