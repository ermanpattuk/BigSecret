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

/**
 * This class is a Byte Bucketizer that uses HBase. Given a byte array, matching bucket value is retrieved from HBase.<br>
 * Number of bucket ids is limited to 2^30.
 */
public class ByteBucketizer extends HBaseBucketizer
{
	/**
	 * Number of bits for input
	 */
	protected int m_inputBitDepth;
	
	/**
	 * Number of buckets in this bucketizer
	 */
	protected int m_numberOfBuckets;
		
	
	/**
	 * Constructor that can be used for creating buckets. This constructor should not be used in Proxy.
	 * @param conf Configuration instance for HBase connection.
	 * @param id Bucketizer ID.
	 * @param inputBits Number of bits for input.
	 * @throws Exception Throws exception if inputBits isn't between 0 and 31.<br>
	 * Throws exception if another bucketizer exists with the given id, but with different inputBits.
	 */
	public ByteBucketizer(Configuration conf, String id, int inputBits) throws Exception 
	{
		//call super class constructor
		super(id, conf);
		
		//check inputs
		if(inputBits < 1) 
		{
			throw new Exception("Input bits should be greater than 0");
		}
		else if(inputBits > 30)
		{
			throw new Exception("Input bits should be less than 31");
		}
		
		//init input bit and bytes value
		m_inputBitDepth = inputBits;
		m_numberOfBuckets = 1;
		for(int a = 0; a<m_inputBitDepth; a++)
			m_numberOfBuckets *= 2;
		
		//check if data exists for this bucketizer
		if(doesExist())
		{
			//check if input bit amount is true
			byte[] hdata = getBucketInfoFromHBase(Bytes.toBytes("inBits"));
			if(hdata == null)
			{
				throw new Exception("inBits data do not exist for bucketizer id=" + id);			
			}
			else
			{
				if(Bytes.toInt(hdata) != m_inputBitDepth)
				{
					throw new Exception("Bucketizer info does not match. Different input bit info");
				}
			}		
		}
	}
	
	
	/**
	 * Constructor for use in Proxy.
	 * @param conf Configuration instance for HBase connection.
	 * @param id Bucketizer ID.
	 * @throws Exception Throws exception if a bucketizer with the given ID does not exist.
	 */
	public ByteBucketizer(String id, Configuration conf) throws Exception
	{
		this(id, 1024 * 64, conf);
	}
	
	
	/**
	 * Constructor for use in Proxy.
	 * @param conf Configuration instance for HBase connection.
	 * @param id Bucketizer ID.
	 * @param cacheSize Size of the cache.
	 * @throws Exception Throws exception if a bucketizer with the given ID does not exist.
	 */
	public ByteBucketizer(String id, int cacheSize, Configuration conf) throws Exception
	{
		//call super class constructor
		super(id, cacheSize, conf);
		
		if(doesExist())
		{
			//init input bit and bytes value
			byte[] hdata = getBucketInfoFromHBase(Bytes.toBytes("inBits"));
			if(hdata == null)
			{
				throw new Exception("inBits data do not exist for bucketizer id=" + id);			
			}
			else
			{
				m_inputBitDepth = Bytes.toInt(hdata);
				m_numberOfBuckets = 1;
				for(int a = 0; a<m_inputBitDepth; a++)
					m_numberOfBuckets *= 2;
			}		
		}
		else
		{
			//if this object is not created for putting bucket values into HBase, then throw exception
			throw new Exception("Bucket with id=" + id + " does not exists");
		}
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getBucketValue(byte[] input) throws Exception 
	{		
		//check input
		if(input == null || input.length == 0)
			throw new Exception("Bucket ID is null or has no data");
		
		//calculate bucket id for this input
		int bucketId = getBucketId(input);
		
		return getBucketValueFromHBase(Bytes.toBytes(bucketId));
	}

	
	/**
	 * {@inheritDoc}
	 */
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

	
	/**
	 * {@inheritDoc}
	 */
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
	 * {@inheritDoc}
	 */
	public int getBucketValueSize() 
	{
		//return bucket value size (size of int)
		return 4;
	}
	
	
	/**
	 * Given an input, calculate bucket ID. If length of input is smaller then number of <br>
	 * bytes for input, append least significant bits with 0. <br>
	 * If input's size is larger, then get the most significant bytes. Otherwise, return input as is.
	 * @param input Byte array input
	 * @return Bucket ID
	 */
	protected int getBucketId(byte[] input) throws Exception
	{
		//check input
		if(input == null || input.length == 0)
			throw new Exception("Input is null or has no data");
		
		//input[0] input[1] .... input[n]
		//input[0] is the most significant byte
		
		//first inputbits of the input should be calculated
		byte[] firstBytes = new byte[4];
		
		//if input size is smaller than inputByteDepth
		if(input.length < 4)
		{
			//get the input bytes 
			int currentPosition = 0;
			for(; currentPosition<input.length; currentPosition++)
				firstBytes[currentPosition] = input[currentPosition];
			
			//remaining bytes are 0
			for(; currentPosition<firstBytes.length; currentPosition++)
				firstBytes[currentPosition] = 0;
		}
		//else if inputarray is enough
		else
		{
			for(int a = 0; a<4; a++)
				firstBytes[a] = input[a];			
		}
		
		//convert this byte array to long
		int bucketId = Bytes.toInt(firstBytes);
		
		//shift value to right so that we have the first inputBit number of bits
		bucketId = bucketId >> (32 - m_inputBitDepth);
			
		//return bucket id
		return bucketId;
	}
	

	/**
	 * This function creates and stores <BucketID, BucketValue> pairs in HBase.
	 * It shouldn't be called when used in Proxy. Create another application that calls this function
	 */
	public void createBuckets() throws Exception 
	{
		//check if there is already information about this bucketizer
		if(doesExist())
		{
			throw new Exception("Bucketizer already exists");
		}
		
		//put bucketizer info, input bit depth, to hbase
		putBucketInfoToHBase(Bytes.toBytes("inBits"), Bytes.toBytes(m_inputBitDepth));
				
		//init bucket limits
		int bucketId = 0;
		
		//start bucket values
		int bucketValue = -1;
		
		//there is a mapping from input bits to output bits
		//on the average, there can be 2^(outbits - inbits) difference between each bucket values 
		int bitDiff = 1;
		for(int a = 0; a<30 - m_inputBitDepth; a++)
			bitDiff *= 2;
		
		//create secure random generator
		SecureRandom ranGen = new SecureRandom();
		
		//print number of buckets
		System.out.println("Total number of buckets: " + m_numberOfBuckets);
		
		//create mappings
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
