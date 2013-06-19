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

package edu.utdallas.bigsecret.proxy;

import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.HTable;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;

import edu.utdallas.bigsecret.crypter.CrypterBase;
import edu.utdallas.bigsecret.util.ByteArray;


/**
 * This class is the one that does all the mumbo jumbo :).<br>
 * All derivations of this class supports Put, Get, Delete.<br>
 * Depending on the Model used (look at BigSecret paper), it may support Scan.<br>
 */
public abstract class ProxyBase
{
	/**
	 * Configuration object for HBase connection to data server
	 */
	protected Configuration m_confData;
	
	/**
	 * Configuration object for HBase connection to bucket data server
	 */
	protected Configuration m_confBucket;
	
	/**
	 * Crypter object
	 */
	protected CrypterBase m_crypter;
	
	/**
	 * HTable instance that connects to Table where data resides
	 */
	protected HTable m_table;
	
	
	/**
	 * Constructor for the class.
	 * @param confData Configuration instance for Data Server.
	 * @param confBucket Configuration instance for Bucket Server.
	 */
	public ProxyBase(Configuration confData, Configuration confBucket)
	{
		m_confData = confData;
		m_confBucket = confBucket;
	}

	
	/**
	 * Closes connection to the HBase data table.
	 * @throws Exception May throw exception based on other classes.
	 */
	public void close() throws Exception
	{
		//close table object
		m_table.close();

		//close crypter object
		m_crypter.close();
	}
	
	
	/**
	 * Connect to the HBase Data Table for the given table.
	 * @param tableName Name of table to connect to.
	 * @throws Exception
	 */
	public void connect(String tableName) throws Exception
	{
		m_table = new HTable(m_confData, tableName);
		m_table.setAutoFlush(false);
	}
	
	
	/**
	 * Flush all data.
	 * @throws Exception
	 */
	public void flushAll() throws Exception
	{
		m_table.flushCommits();
	}

	
	/**
	 * Getter for the Crypter object in use.
	 * @return
	 */
	public CrypterBase getCrypter()
	{
		return m_crypter;
	}
	
	
	/**
	 * Create table with the given name, and list of families.
	 * @param tableName Name of the table.
	 * @param families Set of families to create.
	 * @throws Exception
	 */
	public abstract void createTable(String tableName, Set<String> families) throws Exception;

	
	/**
	 * Remove given table.
	 * @throws Exception
	 */
	public void deleteTable(String tableName) throws Exception
	{
		//create hbase admin instance
		HBaseAdmin admin = new HBaseAdmin(m_confData);
		
		//check if table exists
		if(admin.tableExists(tableName))
		{
			admin.disableTable(tableName);
			admin.deleteTable(tableName);
		}
		
		admin.close();
	}
	
	/**
	 * Get name of the table, that is currently connected to.
	 * @return
	 */
	public byte[] getTableName() 
	{
		return m_table.getTableName();
	}

	
	/**
	 * Performs a delete operation on the HBase Data Table.
	 * @param arg0
	 * @throws Exception
	 */
	public abstract void delete(Delete arg0) throws Exception;
	
	
	/**
	 * This function is called internally, if Scan needs to be performed on encrypted data.<br>
	 * It is assumed that encRowSet contains encrypted row representations of a single plain row.<br>
	 * @param scanItem Original Scan item.
	 * @param encRowSet Set of encrypted representations of a single row.
	 * @return Result for Key-Value entries that satisfy the scanItem.
	 * @throws Exception
	 */
	public abstract Result getForScan(Scan scanItem, Set<ByteArray> encRowSet) throws Exception;

	
	/**
	 * Get Scanner instance for the given Scan item.
	 * @param arg0 Scan instance.
	 * @return ResultScanner for the given Scan instance.
	 * @throws Exception
	 */
	public abstract ResultScanner getScanner(Scan arg0) throws Exception;


	/**
	 * Perform a Put operation on the currently connected table.
	 * @param arg0 Put instance.
	 * @throws Exception
	 */
	public abstract void put(Put arg0) throws Exception;

	
	/**
	 * Perform a Get operation on the currently connected table.
	 * @param arg0 Get instance.
	 * @return Set of results for the given Get instance.
	 * @throws Exception
	 */
	public abstract Result get(Get arg0) throws Exception;
	
	
	/**
	 * Given a family map, check if given <family, qualifier> data exists in it.<br>
	 * If there is no family, method returns true for every pair<br>
	 * Else if family is in family map as inserted family, then for any qualifier, method returns true<br>
	 * Else if <family, qualifier> pair exists, method returns true<br>
	 * Return false otherwise
	 * @param familyMap Family Map data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @return true if pair exists, false otherwise
	 * @throws Exception 
	 */
	protected boolean doesFamilyQualifierExist(Map<byte[], NavigableSet<byte[]>> familyMap, byte[] family, byte[] qualifier) throws Exception
	{
		//check inputs
		if(familyMap == null)
			throw new Exception("Family map object is null");
		else if(family == null)
			throw new Exception("Family is null");
		else if(qualifier == null)
			throw new Exception("Qualifier is null");			
						
		//get qualifier list for the family
		Set<byte[]> qualifierList = familyMap.get(family);
		
		if(familyMap.isEmpty())
		{
			return true;
		}
		else if(! familyMap.containsKey(family))
		{
			//if family is not included, return false
			return false;
		}
		else if(qualifierList == null)
		{
			//if it is, then return true since any qualifier is requested originally
			return true;
		}
		else if(qualifierList.contains(qualifier))
		{
			//check if qualifier exists
			//if so, return true
			return true;
		}
		else
		{
			//otherwise return false;
			return false;
		}
	}
	
	
	/**
	 * Add KeyValue to the list. This is a recursive function, and does binary search.
	 * @param low Low index
	 * @param high High index
	 * @param newItem Item to be inserted
	 * @param list List that item will be inserted
	 */
	protected void addKeyValueToList(int low, int high, KeyValue newItem, List<KeyValue> list)
	{
		if(low > high)
		{
			list.add(low, newItem);
		}
		else
		{		
			KeyValue.KVComparator cmp = new KeyValue.KVComparator();
			int mid = (low + high) / 2;
			
			if(cmp.compare(newItem, list.get(mid)) < 0)
				addKeyValueToList(low, mid-1, newItem, list);
			else
				addKeyValueToList(mid+1, high, newItem, list);
		}
	}
}
