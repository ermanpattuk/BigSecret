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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.HTable;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.hbase.client.Result;

import edu.utdallas.bigsecret.util.Cache;


/**
 * This class extends Bucketizer. Sub-classes of this class should use HBase to store<br>
 * bucket mapping, and get bucket values.
 */
public abstract class HBaseBucketizer extends BucketizerBase
{
	/**
	 * User-defined ID for this bucketizer.
	 */
	protected byte[] m_id;
		
	/**
	 * Configuration object for HBase connection
	 */
	protected Configuration m_conf;
	
	/**
	 * Static name for BucketValueTable
	 */
	protected static String BUCKET_VALUE_TABLE_NAME = "bucketValues";
	
	/**
	 * Static name for BucketValueTable family
	 */
	protected static byte[] BUCKET_VALUE_FAMILY_NAME = Bytes.toBytes("f");
	
	/**
	 * HTable instance for BucketMapTable
	 */
	protected HTable m_tableBucketMap;
	
	/**
	 * Static name for BucketInfoTable
	 */
	protected static String BUCKET_INFO_TABLE_NAME = "bucketInfo";

	/**
	 * Static name for BucketInfoTable family
	 */
	protected static byte[] BUCKET_INFO_FAMILY_NAME = Bytes.toBytes("f");
	
	/**
	 * HTable instance for BucketInfoTable
	 */
	protected HTable m_tableBucketInfo;
	
	/**
	 * Cache to hold already queried bucketId and bucketValue pairings.
	 */
	protected Cache m_cache;
	
	
	/**
	 * Constructor that takes two parameters, and assigns one statically.<br>
	 * Sets size of the cache to 64K.
	 * @param id Unique ID for the bucketizer.
	 * @param conf Configuration instance that points to bucketizer's server.
	 * @throws Exception Throws exception if ID is null or empty.<br>
	 * May throw exception based on HBase operations.
	 */
	public HBaseBucketizer(String id, Configuration conf) throws Exception
	{
		this(id, 1024 * 64, conf);
	}
	
	
	/**
	 * Constructor that takes three parameters.
	 * @param id Unique ID for the bucketizer.
	 * @param conf Configuration instance that points to bucketizer's server.
	 * @param cacheSize Size of the cache.
	 * @throws Exception Throws exception if ID is null or empty.<br>
	 * Throws exception if cache size is invalid.<br>
	 * May throw exception based on HBase operations.
	 */
	public HBaseBucketizer(String id, int cacheSize, Configuration conf) throws Exception
	{
		//set bucketizer id
		if(id == null || id.length() ==0)
			throw new Exception("ID cannot be null or \"\"");
		m_id = Bytes.toBytes(id);
		
		//set configuration instance
		m_conf = conf;
		
		//check cache size
		if(cacheSize < 0)
			throw new Exception("Cache size cannot be negative.");
		
		//set cache
		m_cache = new Cache(cacheSize);
		
		//create hbaseadmin instance
		HBaseAdmin admin = new HBaseAdmin(m_conf);

		//check if the bucket value table exists
		if(!admin.tableExists(BUCKET_VALUE_TABLE_NAME))
		{
			//create table descriptor
			HTableDescriptor desc = new HTableDescriptor(BUCKET_VALUE_TABLE_NAME);
			
			//create family descriptor and add it
			HColumnDescriptor colDesc = new HColumnDescriptor(BUCKET_VALUE_FAMILY_NAME);
			desc.addFamily(colDesc);

			//create table
			admin.createTable(desc);
		}

		//check if the bucket info table exists
		if(!admin.tableExists(BUCKET_INFO_TABLE_NAME))
		{
			//create table descriptor
			HTableDescriptor desc = new HTableDescriptor(BUCKET_INFO_TABLE_NAME);
			
			//create family descriptor and add it
			HColumnDescriptor colDesc = new HColumnDescriptor(BUCKET_INFO_FAMILY_NAME);
			desc.addFamily(colDesc);

			//create table
			admin.createTable(desc);
		}
		
		//create htable instance for bucket mapping
		m_tableBucketMap = new HTable(m_conf, BUCKET_VALUE_TABLE_NAME);
		m_tableBucketMap.setAutoFlush(false);
		
		//create htable instance for bucket info
		m_tableBucketInfo = new HTable(m_conf, BUCKET_INFO_TABLE_NAME);
		m_tableBucketInfo.setAutoFlush(false);
		
		//close admin
		admin.close();
	}
	
	
	/**
	 * Close open HTable instances
	 * @throws Exception
	 */
	public void close() throws Exception
	{
		//close tables
		m_tableBucketInfo.close();
		m_tableBucketMap.close();
	}
	
	
	/**
	 * Check if this table's info is in BucketInfoTable
	 * @return true if info exists, false otherwise
	 * @throws Exception
	 */
	protected boolean doesExist() throws Exception
	{
		//create a get item to get data from table info table
		Get getItem = new Get(m_id);
		Result result = m_tableBucketInfo.get(getItem);
		
		//if there is no info, that means table does not exist
		if(result.size() == 0)
			return false;
		else
			return true;
	}
	
	
	/**
	 * Get data from BucketInfoTable for this bucketizer and given qualifier
	 * @param qualifier Qualifier name
	 * @return Value if data exists, null otherwise
	 * @throws Exception
	 */
	protected byte[] getBucketInfoFromHBase(byte[] qualifier) throws Exception
	{
		//check inputs
		if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier is null or has no data");
		
		//create a get item to get data from table info table
		Get getItem = new Get(m_id);
		getItem.addColumn(BUCKET_INFO_FAMILY_NAME, qualifier);
		Result result = m_tableBucketInfo.get(getItem);
		
		//return resulting value if any
		return result.value();
	}
	
	
	/**
	 * Put data to BucketInfoTable for given qualifier and value
	 * @param qualifier Qualifier data
	 * @param value Value data
	 * @throws Exception
	 */
	protected void putBucketInfoToHBase(byte[] qualifier, byte[] value) throws Exception
	{
		//check inputs
		if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier is null or has no data");
		else if(value == null || value.length == 0)
			throw new Exception("Value is null or has no data");
		
		//create a put item and insert data to it
		Put putItem = new Put(m_id);
		putItem.add(BUCKET_INFO_FAMILY_NAME, qualifier, value);
				
		//add data to the table
		m_tableBucketInfo.put(putItem);
	}
	
	
	/**
	 * Put data to BucketValueTable for the given <BucketID, BucketValue>
	 * @param bucketId BucketID
	 * @param bucketValue Value for this bucket
	 * @throws Exception
	 */
	protected void putBucketValueToHBase(byte[] bucketId, byte[] bucketValue) throws Exception
	{
		//check inputs
		if(bucketId == null || bucketId.length == 0)
			throw new Exception("Bucket ID is null or has no data");
		else if(bucketValue == null || bucketValue.length == 0)
			throw new Exception("Bucket Value is null or has no data");
		
		//create a put item with rowKey = bucket id
		Put putItem = new Put(bucketId);
		
		//put value as qualifier=bucketizerId
		putItem.add(BUCKET_VALUE_FAMILY_NAME, m_id, bucketValue);
		
		//add data to hbase
		m_tableBucketMap.put(putItem);
	}
	
	
	/**
	 * Remove all information that belongs to this bucketizer.
	 * @throws Exception
	 */
	protected void removeBucketInfoFromHBase() throws Exception
	{
		removeBucketInfoFromHBase(null);
	}
	
	
	/**
	 * Remove bucketizer data that has the given attribute.
	 * @param qualifier Name of the attribute that is to be deleted.
	 * @throws Exception
	 */
	protected void removeBucketInfoFromHBase(byte[] qualifier) throws Exception
	{
		Delete deleteItem = new Delete(m_id);
		
		if(qualifier != null)
		{
			deleteItem.deleteColumns(BUCKET_INFO_FAMILY_NAME, qualifier);
		}
		
		m_tableBucketInfo.delete(deleteItem);
	}
	
	
	/**
	 * Get bucket value for the given bucket ID
	 * @param bucketId Bucket ID
	 * @return null if this bucket does not exist, return value otherwise
	 * @throws Exception Throws exception if bucketId is null or empty.
	 */
	protected byte[] getBucketValueFromHBase(byte[] bucketId) throws Exception
	{
		//check inputs
		if(bucketId == null || bucketId.length == 0)
			throw new Exception("Bucket ID is null or has no data");
		
		byte[] value = m_cache.get(bucketId);
		
		if(value == null)
		{			
			//create a get item to get data from table info table
			Get getItem = new Get(bucketId);
			getItem.addColumn(BUCKET_VALUE_FAMILY_NAME, m_id);
			
			Result result = m_tableBucketMap.get(getItem);
			
			if(result != null)
				m_cache.put(bucketId, result.value());
			
			return result.value();
		}
		else
		{
			return value;
		}
	}
	
	
	/**
	 * Remove the given bucketId-bucketValue pair from this bucketizer.
	 * @param bucketId BucketId to be deleted.
	 * @throws Exception Throws exception if bucketId is null or empty.
	 */
	protected void removeBucketValueFromHBase(byte[] bucketId) throws Exception
	{
		//check inputs
		if(bucketId == null || bucketId.length == 0)
			throw new Exception("Bucket ID is null or has no data");
		
		Delete deleteItem = new Delete(bucketId);
		deleteItem.deleteColumns(BUCKET_VALUE_FAMILY_NAME, m_id);
		
		m_tableBucketMap.delete(deleteItem);
	}
	
	
	/**
	 * To improve initial performance, cache is filled with a set of values.
	 * @throws Exception
	 */
	public void fillCache() throws Exception
	{
		int cacheSize = m_cache.getSize();
		for(int a = 0; a<cacheSize; a++)
		{			
			getBucketValueFromHBase(Bytes.toBytes(a));
		}
	}
}