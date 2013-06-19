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

/**
 * Abstract class for the bucketization process.
 */
public abstract class BucketizerBase 
{
	/**
	 * Default constructor
	 * @throws Exception
	 */
	public BucketizerBase() throws Exception
	{		
	}
	
	
	/**
	 * Get bucket value for the input.
	 * @param input Input byte array.
	 * @return Byte array representation of bucket.
	 * @throws Exception
	 */
	public abstract byte[] getBucketValue(byte[] input) throws Exception;
	
	
	/**
	 * Get next bucket value for the input
	 * @param input input byte array
	 * @return null if there is no next bucket, otherwise return byte array representation of next bucket
	 * @throws Exception
	 */
	public abstract byte[] getNextBucketValue(byte[] input) throws Exception;
	
	
	/**
	 * Get previous bucket value for the input
	 * @param input input byte array
	 * @return null if there is no previous bucket, otherwise return byte array representation of next bucket
	 * @throws Exception
	 */
	public abstract byte[] getPrevBucketValue(byte[] input) throws Exception;
	
	
	/**
	 * Get byte size of a bucket value
	 * @return number of bytes to represent a bucket value
	 */
	public abstract int getBucketValueSize();
	
	
	/**
	 * Create buckets for this bucketizer
	 * @throws Exception
	 */
	public abstract void createBuckets() throws Exception;
	
	
	/**
	 * Removes buckets for this bucketizer.
	 * @throws Exception
	 */
	public abstract void removeBuckets() throws Exception;
}
