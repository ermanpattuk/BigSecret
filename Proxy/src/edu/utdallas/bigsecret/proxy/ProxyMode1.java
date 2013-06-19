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

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;
import java.util.TreeSet;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.filter.ColumnPrefixFilter;
import org.apache.hadoop.hbase.filter.FilterList;
import org.apache.hadoop.hbase.filter.KeyOnlyFilter;
import org.apache.hadoop.hbase.filter.MultipleColumnPrefixFilter;
import org.apache.hadoop.hbase.util.Bytes;

import edu.utdallas.bigsecret.bucketizer.HBaseBucketizer;
import edu.utdallas.bigsecret.cipher.Cipher;
import edu.utdallas.bigsecret.crypter.CrypterMode1;
import edu.utdallas.bigsecret.scanner.EncryptedScanner;
import edu.utdallas.bigsecret.util.ByteArray;
import edu.utdallas.bigsecret.util.Utilities;


/**
 * This model of BigSecret supports all four operations, Get, Put, Delete, and Scan.<br>
 * Details of the model are presented in the BigSecret paper. 
 */
public class ProxyMode1 extends ProxyBase
{	
	/**
	 * Constructor for this class.
	 * @param confData Configuration instance that points to HBase that holds actual data.
	 * @param confBucket Configuration instance that points to HBase that holds bucket data.
	 * @param rowBucketizer Bucketizer for the row key-part.
	 * @param famBucketizer Bucketizer for the family key-part.
	 * @param quaBucketizer Bucketizer for the qualifier key-part.
	 * @param tsBucketizer Bucketizer for the timstamp key-part.
	 * @param keyCipher Cipher for the whole key.
	 * @param valCipher Cipher for the value part.
	 * @throws Exception
	 */
	public ProxyMode1(Configuration confData, 
					Configuration confBucket,
					HBaseBucketizer rowBucketizer,
					HBaseBucketizer famBucketizer,
					HBaseBucketizer quaBucketizer,
					HBaseBucketizer tsBucketizer,
					Cipher keyCipher,
					Cipher valCipher) throws Exception
	{
		super(confData, confBucket);
		
		m_crypter = new CrypterMode1(rowBucketizer, famBucketizer, quaBucketizer, tsBucketizer, keyCipher, valCipher);

	}
	
	/**
	 * {@inheritDoc}
	 */
	public void createTable(String tableName, Set<String> families) throws Exception 
	{
		//check inputs
		if(tableName == null)
			throw new Exception("Table name is null");
		else if(families == null || families.size() == 0)
			throw new Exception("Familiy set is null or has no data");
		
		//create hbase admin instance
		HBaseAdmin admin = new HBaseAdmin(m_confData);
		
		//check if table exists
		if(admin.tableExists(tableName))
		{
			admin.close();
			return;
		}
		
		//create table descriptor
		HTableDescriptor desc = new HTableDescriptor(tableName);
		
		//get families iterator
		Iterator<String> it = families.iterator();
		
		//add each family name
		while(it.hasNext())
		{			
			//create family descriptor and add it
			HColumnDescriptor colDesc = new HColumnDescriptor(m_crypter.getIndexFamilyData(Bytes.toBytes(it.next())));
			desc.addFamily(colDesc);
		}
		
		//create table
		admin.createTable(desc);
		
		admin.close();
	}
	

	/**
	 * {@inheritDoc}
	 */
	public void delete(Delete deleteItem) throws Exception
	{
		if(deleteItem == null)
			throw new Exception("No item to delete");
			
		byte[] plainRow = deleteItem.getRow();
		
		Map<byte[], List<KeyValue>> famMap = deleteItem.getFamilyMap();
		
		List<Delete> deleteList = new ArrayList<Delete>();
		
		if(famMap.size() == 0)
		{
			long timestamp = deleteItem.getTimeStamp();
			
			delete(deleteList, plainRow, null, null, timestamp, false);
		}
		else
		{
			Set<byte[]> famSet = famMap.keySet();
			Iterator<byte[]> itrFam = famSet.iterator();
			
			while(itrFam.hasNext())
			{
				byte[] plainFam = itrFam.next();
				
				List<KeyValue> plainKeyList = famMap.get(plainFam);
				
				for(int a = 0; a<plainKeyList.size(); a++)
				{
					KeyValue currentKV = plainKeyList.get(a);
					
					if(currentKV.getType() == KeyValue.Type.DeleteFamily.getCode())
					{
						long plainTs = currentKV.getTimestamp();

						delete(deleteList, plainRow, plainFam, null, plainTs, false);
					}
					else if(currentKV.getType() == KeyValue.Type.DeleteColumn.getCode())
					{
						long plainTs = currentKV.getTimestamp();
						byte[] plainQua = currentKV.getQualifier();

						delete(deleteList, plainRow, plainFam, plainQua, plainTs, true);						
					}
					else if(currentKV.getType() == KeyValue.Type.Delete.getCode())
					{
						long plainTs = currentKV.getTimestamp();
						byte[] plainQua = currentKV.getQualifier();

						delete(deleteList, plainRow, plainFam, plainQua, plainTs, false);						
					}
				}
			}
		}
		
		m_table.delete(deleteList);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	private void delete(List<Delete> deleteList, byte[] row, byte[] fam, byte[] qua, long timestamp, boolean allQual) throws Exception
	{
		byte[] encRow = m_crypter.getIndexRowData(row);
		
		Get getItem = new Get(encRow);
		
		if(fam == null && qua == null && timestamp == HConstants.LATEST_TIMESTAMP && allQual == false)
		{
			Result result = m_table.get(getItem);
			if(result == null)
				return;
			List<KeyValue> keyList = result.list();				
			if(keyList == null)
				return;
			
			for(int a = 0; a<keyList.size(); a++)
			{					
				byte[] decRow = m_crypter.unwrapRow(keyList.get(a));
				
				if(Arrays.equals(decRow, row))
				{
					byte[] encFam = keyList.get(a).getFamily();
					byte[] encQua = keyList.get(a).getQualifier();
					long encTs = keyList.get(a).getTimestamp();
					
					Delete tempDelete = new Delete(encRow);
					tempDelete.deleteColumn(encFam, encQua, encTs);
					
					deleteList.add(tempDelete);
				}
			}
		}
		else if(fam == null && qua == null && timestamp != HConstants.LATEST_TIMESTAMP && allQual == false)
		{
			long indexTimestamp = Utilities.getLong(m_crypter.getIndexTimestampData(timestamp));
			getItem.setTimeRange(0,  indexTimestamp+1);
			
			Result result = m_table.get(getItem);
			if(result == null)
				return;
			List<KeyValue> keyList = result.list();				
			if(keyList == null)
				return;
			
			for(int a = 0; a<keyList.size(); a++)
			{					
				byte[] decRow = m_crypter.unwrapRow(keyList.get(a));
				long decTs = m_crypter.unwrapTimestamp(keyList.get(a));
				
				if(Arrays.equals(decRow, row) && decTs <= timestamp)
				{
					byte[] encFam = keyList.get(a).getFamily();
					byte[] encQua = keyList.get(a).getQualifier();
					long encTs = keyList.get(a).getTimestamp();
					
					Delete tempDelete = new Delete(encRow);
					tempDelete.deleteColumn(encFam, encQua, encTs);
					
					deleteList.add(tempDelete);
				}
			}
		}
		else if(fam != null && qua == null && timestamp == HConstants.LATEST_TIMESTAMP && allQual == false)
		{
			getItem.addFamily(m_crypter.getIndexFamilyData(fam));
			
			Result result = m_table.get(getItem);
			if(result == null)
				return;
			List<KeyValue> keyList = result.list();				
			if(keyList == null)
				return;
			
			for(int a = 0; a<keyList.size(); a++)
			{					
				byte[] decRow = m_crypter.unwrapRow(keyList.get(a));
				byte[] decFam = m_crypter.unwrapFamily(keyList.get(a));
				
				if(Arrays.equals(decRow, row) && Arrays.equals(decFam, fam))
				{
					byte[] encFam = keyList.get(a).getFamily();
					byte[] encQua = keyList.get(a).getQualifier();
					long encTs = keyList.get(a).getTimestamp();
					
					Delete tempDelete = new Delete(encRow);
					tempDelete.deleteColumn(encFam, encQua, encTs);
					
					deleteList.add(tempDelete);
				}
			}
		}
		else if(fam != null && qua == null && timestamp != HConstants.LATEST_TIMESTAMP && allQual == false)
		{
			getItem.addFamily(m_crypter.getIndexFamilyData(fam));
			
			long indexTimestamp = Utilities.getLong(m_crypter.getIndexTimestampData(timestamp));
			getItem.setTimeRange(0,  indexTimestamp+1);
			
			Result result = m_table.get(getItem);
			if(result == null)
				return;
			List<KeyValue> keyList = result.list();				
			if(keyList == null)
				return;
			
			for(int a = 0; a<keyList.size(); a++)
			{					
				byte[] decRow = m_crypter.unwrapRow(keyList.get(a));
				long decTs = m_crypter.unwrapTimestamp(keyList.get(a));
				byte[] decFam = m_crypter.unwrapFamily(keyList.get(a));
				
				if(Arrays.equals(decRow, row) && decTs <= timestamp && Arrays.equals(decFam, fam))
				{
					byte[] encFam = keyList.get(a).getFamily();
					byte[] encQua = keyList.get(a).getQualifier();
					long encTs = keyList.get(a).getTimestamp();
					
					Delete tempDelete = new Delete(encRow);
					tempDelete.deleteColumn(encFam, encQua, encTs);
					
					deleteList.add(tempDelete);
				}
			}			
		}
		else if(fam != null && qua != null && timestamp == HConstants.LATEST_TIMESTAMP && allQual == true)
		{
			getItem.addFamily(m_crypter.getIndexFamilyData(fam));
			getItem.setFilter(new ColumnPrefixFilter(m_crypter.getIndexQualifierData(qua)));
			
			Result result = m_table.get(getItem);
			if(result == null)
				return;
			List<KeyValue> keyList = result.list();				
			if(keyList == null)
				return;
			
			for(int a = 0; a<keyList.size(); a++)
			{					
				byte[] decRow = m_crypter.unwrapRow(keyList.get(a));
				byte[] decFam = m_crypter.unwrapFamily(keyList.get(a));
				byte[] decQua = m_crypter.unwrapQualifier(keyList.get(a));
				
				if(Arrays.equals(decRow, row) && Arrays.equals(decFam, fam) && Arrays.equals(decQua, qua))
				{
					byte[] encFam = keyList.get(a).getFamily();
					byte[] encQua = keyList.get(a).getQualifier();
					long encTs = keyList.get(a).getTimestamp();
					
					Delete tempDelete = new Delete(encRow);
					tempDelete.deleteColumn(encFam, encQua, encTs);
					
					deleteList.add(tempDelete);
				}
			}			
		}
		else if(fam != null && qua != null && timestamp != HConstants.LATEST_TIMESTAMP && allQual == true)
		{
			getItem.addFamily(m_crypter.getIndexFamilyData(fam));
			getItem.setFilter(new ColumnPrefixFilter(m_crypter.getIndexQualifierData(qua)));
			
			long indexTimestamp = Utilities.getLong(m_crypter.getIndexTimestampData(timestamp));
			getItem.setTimeRange(0,  indexTimestamp+1);
			
			Result result = m_table.get(getItem);
			if(result == null)
				return;
			List<KeyValue> keyList = result.list();				
			if(keyList == null)
				return;
			
			for(int a = 0; a<keyList.size(); a++)
			{					
				byte[] decRow = m_crypter.unwrapRow(keyList.get(a));
				byte[] decFam = m_crypter.unwrapFamily(keyList.get(a));
				byte[] decQua = m_crypter.unwrapQualifier(keyList.get(a));
				long decTs = m_crypter.unwrapTimestamp(keyList.get(a));
				
				if(Arrays.equals(decRow, row) && decTs <= timestamp && Arrays.equals(decFam, fam) && Arrays.equals(decQua, qua))
				{
					byte[] encFam = keyList.get(a).getFamily();
					byte[] encQua = keyList.get(a).getQualifier();
					long encTs = keyList.get(a).getTimestamp();
					
					Delete tempDelete = new Delete(encRow);
					tempDelete.deleteColumn(encFam, encQua, encTs);
					
					deleteList.add(tempDelete);
				}
			}			
		}
		else if(fam != null && qua != null && timestamp != HConstants.LATEST_TIMESTAMP && allQual == false)
		{
			getItem.setTimeStamp(Utilities.getLong(m_crypter.getIndexTimestampData(timestamp)));
			getItem.addFamily(m_crypter.getIndexFamilyData(fam));
			getItem.setFilter(new ColumnPrefixFilter(m_crypter.getIndexQualifierData(qua)));
			
			long indexTimestamp = Utilities.getLong(m_crypter.getIndexTimestampData(timestamp));
			getItem.setTimeRange(0,  indexTimestamp+1);
			
			Result result = m_table.get(getItem);
			if(result == null)
				return;
			List<KeyValue> keyList = result.list();				
			if(keyList == null)
				return;
			
			for(int a = 0; a<keyList.size(); a++)
			{					
				byte[] decRow = m_crypter.unwrapRow(keyList.get(a));
				byte[] decFam = m_crypter.unwrapFamily(keyList.get(a));
				byte[] decQua = m_crypter.unwrapQualifier(keyList.get(a));
				long decTs = m_crypter.unwrapTimestamp(keyList.get(a));
				
				if(Arrays.equals(decRow, row) && decTs == timestamp && Arrays.equals(decFam, fam) && Arrays.equals(decQua, qua))
				{
					byte[] encFam = keyList.get(a).getFamily();
					byte[] encQua = keyList.get(a).getQualifier();
					long encTs = keyList.get(a).getTimestamp();
					
					Delete tempDelete = new Delete(encRow);
					tempDelete.deleteColumn(encFam, encQua, encTs);
					
					deleteList.add(tempDelete);
				}
			}	
		}
		else if(fam != null && qua != null && timestamp == HConstants.LATEST_TIMESTAMP && allQual == false)
		{
			//This part is way too long :) We need to sort and take the latest KeyValue item.
		}
	}

	
	/**
	 * {@inheritDoc}
	 */
	public Result get(Get getItem) throws Exception 
	{
		//check inputs
		if(getItem == null)
			throw new IOException("Get item is null");

		//plain text row key
		byte[] plainRowKey = getItem.getRow();
		byte[] encRowKey = m_crypter.getIndexRowData(plainRowKey);
		
		//resulting keyvalue data
		List<KeyValue> resultKeyValues = new ArrayList<KeyValue>();
		
		//encrypted time stamp min and max values
		long plainMinTimestamp = getItem.getTimeRange().getMin();
		long plainMaxTimestamp = getItem.getTimeRange().getMax();
		
		long encMinTimestamp = Utilities.getLong(m_crypter.getTimestampBucket(plainMinTimestamp));
		
		byte[] tempData = m_crypter.getTimestampNextBucket(plainMaxTimestamp);
		
		long encMaxTimestamp;
		
		if(tempData == null)
		{
			encMaxTimestamp = 9223372036854775807L;
		}
		else
		{
			encMaxTimestamp = Utilities.getLong(tempData);
		}
		
		Get encGet = new Get(encRowKey);
		encGet.setTimeRange(encMinTimestamp, encMaxTimestamp);
		
		//get family map from plain text get item
		Set<byte[]> familySet = getItem.familySet();
		Map<byte[], NavigableSet<byte[]>> familyMap = getItem.getFamilyMap();
		
		Iterator<byte[]> itrFamily = familySet.iterator();
		Set<byte[]> qualifierSet = new TreeSet<byte[]>(Bytes.BYTES_COMPARATOR);
		
		while(itrFamily.hasNext())
		{
			//get current family
			byte[] currentFamily = itrFamily.next();
			
			//wrap family
			byte[] encCurrentFamily = m_crypter.getIndexFamilyData(currentFamily);
			
			encGet.addFamily(encCurrentFamily);
			
			//get qualifiers list for this family
			Set<byte[]> currentQualifierSet = getItem.getFamilyMap().get(currentFamily);
			
			if(currentQualifierSet != null)
			{
				Iterator<byte[]> itrQualifier = currentQualifierSet.iterator();
				
				while(itrQualifier.hasNext())
				{
					qualifierSet.add(m_crypter.getIndexQualifierData(itrQualifier.next()));
				}
			}				
		}
		
		byte[][] qualifierPrefixes = new byte[qualifierSet.size()][];
		Iterator<byte[]> itr2 = qualifierSet.iterator();
		int counter = 0;
		while(itr2.hasNext())
		{
			qualifierPrefixes[counter] = itr2.next();
			counter++;
		}
		
		encGet.setFilter(new MultipleColumnPrefixFilter(qualifierPrefixes));
		
		Result result = m_table.get(encGet);
		List<KeyValue> encKeyValues = result.list();
		
		if(encKeyValues != null)
		{
			Iterator<KeyValue> itrKeyValue = encKeyValues.iterator();
			
			while(itrKeyValue.hasNext())
			{
				KeyValue currentValue = itrKeyValue.next();
				
				byte[] decRow = m_crypter.unwrapRow(currentValue);
				if(Arrays.equals(decRow, plainRowKey))
				{
					long decTimestamp = m_crypter.unwrapTimestamp(currentValue);
					
					if(plainMinTimestamp <= decTimestamp && decTimestamp <= plainMaxTimestamp)
					{
						byte[] decFamily = m_crypter.unwrapFamily(currentValue);
						byte[] decQualifier = m_crypter.unwrapQualifier(currentValue);
						if(doesFamilyQualifierExist(familyMap, decFamily, decQualifier))
						{
							KeyValue decTempItem = new KeyValue(plainRowKey,
																decFamily,
																decQualifier,
																decTimestamp,
																m_crypter.unwrapValue(currentValue));

							addKeyValueToList(0, resultKeyValues.size()-1, decTempItem, resultKeyValues);							
						}									
					}
				}
			}
		}
		
		//if there are no result keys, return empty Result object
		//otherwise return result keys.
		if(resultKeyValues.size() == 0)
			return new Result();
		else
			return new Result(resultKeyValues);
	}
	

	/**
	 * {@inheritDoc}
	 */
	public Result getForScan(Scan scanItem, Set<ByteArray> encQuaSet) throws Exception 
	{
		if(scanItem == null)
			throw new Exception("scanItem object is null");
		else if(encQuaSet == null)
			throw new Exception("Encrypted qualifier set object is null");
		
		//resulting keyvalue data
		List<KeyValue> resultKeyValues = new ArrayList<KeyValue>();
		
		//time stamps
		long minTs = scanItem.getTimeRange().getMin();
		long maxTs = scanItem.getTimeRange().getMax();
		long encMinTimestamp = Utilities.getLong(m_crypter.getTimestampBucket(minTs));
		long encMaxTimestamp = Utilities.getLong(m_crypter.getTimestampNextBucket(maxTs));
				
		Map<byte[], NavigableSet<byte[]>> plainFamilyMap = scanItem.getFamilyMap();
		Iterator<ByteArray> encQuaItr = encQuaSet.iterator();
		
		byte[] firstValue = encQuaItr.next().getData();
		byte[] currentPlainRow = m_crypter.unwrapRow(null, null, firstValue, 0, null);
		Get encGet = new Get(m_crypter.getIndexRowData(currentPlainRow));
		
		byte[][] qualifierPrefixes = new byte[encQuaSet.size()][];
		qualifierPrefixes[0] = firstValue;
		int counter = 1;
		while(encQuaItr.hasNext())
		{
			qualifierPrefixes[counter] = encQuaItr.next().getData();
			counter++;
		}
		
		encGet.setFilter(new MultipleColumnPrefixFilter(qualifierPrefixes));
		encGet.setTimeRange(encMinTimestamp, encMaxTimestamp);
		
		Result encResult = m_table.get(encGet);
		List<KeyValue> encKeyValues = encResult.list();
		
		Iterator<KeyValue> itrKeyValue = encKeyValues.iterator();
		while(itrKeyValue.hasNext())
		{
			//for every key value
			KeyValue currentEncKeyValue = itrKeyValue.next();
			
			//decrypt family, qualifier and timestamp
			long decTimestamp = m_crypter.unwrapTimestamp(currentEncKeyValue);
			
			//check if decrypted time stamp is in plain text timestamp range and family qualifier pair exists in the original get
			if(minTs <= decTimestamp && decTimestamp <= maxTs) 
			{
				byte[] decFamily = m_crypter.unwrapFamily(currentEncKeyValue);
				byte[] decQualifier = m_crypter.unwrapQualifier(currentEncKeyValue);
				
				if(doesFamilyQualifierExist(plainFamilyMap, decFamily, decQualifier))
				{
					KeyValue tempKeyvalueItem = new KeyValue(currentPlainRow, decFamily, decQualifier, decTimestamp, 
														m_crypter.unwrapValue(currentEncKeyValue));

					addKeyValueToList(0, resultKeyValues.size()-1, tempKeyvalueItem, resultKeyValues);
				}
			}
		}
		
		//if there are no result keys, return empty Result object
		//otherwise return result keys.
		if(resultKeyValues.size() == 0)
			return new Result();
		else
			return new Result(resultKeyValues);
	}

	
	/**
	 * {@inheritDoc}
	 */
	public ResultScanner getScanner(Scan scanItem) throws Exception 
	{
	//check inputs
		if(scanItem == null)
			throw new IOException("Scan item is null");
		
		//create encrypted scan instance
		Scan encScanItem = new Scan();
		
		//set encrypted start row
		byte[] plainStartRow = scanItem.getStartRow();
		if(plainStartRow != HConstants.EMPTY_START_ROW)
		{
			byte[] encStartRow = m_crypter.getRowBucket(plainStartRow);
			if(encStartRow != null)
				encScanItem.setStartRow(encStartRow);
		}
		
		//set encrypted stop row
		byte[] plainEndRow = scanItem.getStopRow();
		if(plainEndRow != HConstants.EMPTY_END_ROW)
		{
			byte[] encEndRow = m_crypter.getRowNextBucket(plainEndRow);
			if(encEndRow != null)
				encScanItem.setStopRow(encEndRow);
		}
		
		//encrypted time stamp min and max values
		long plainMinTimestamp = scanItem.getTimeRange().getMin();
		long plainMaxTimestamp = scanItem.getTimeRange().getMax();
		long encryptedMinTimestamp = Utilities.getLong(m_crypter.getTimestampBucket(plainMinTimestamp));
		byte[] tempByte = m_crypter.getTimestampNextBucket(plainMaxTimestamp);
		long encryptedMaxTimestamp;
		if(tempByte == null)
		{
			encryptedMaxTimestamp = Long.MAX_VALUE;
		}
		else
		{
			encryptedMaxTimestamp = Utilities.getLong(tempByte);
		}
		
		//set timestamp range
		encScanItem.setTimeRange(encryptedMinTimestamp, encryptedMaxTimestamp);
		
		//get family map
		Map<byte[], NavigableSet<byte[]>> famMap = scanItem.getFamilyMap();
		Set<byte[]> famSet = famMap.keySet();
		Iterator<byte[]> itrFamily = famSet.iterator();
		
		//prefix set for the qualifiers filter
		Set<byte[]> qualifierSet = new TreeSet<byte[]>(Bytes.BYTES_COMPARATOR);
		
		//for all families
		while(itrFamily.hasNext())
		{
			//get current family
			byte[] curPlainFamily = itrFamily.next();
			byte[] curEncFamily = m_crypter.getIndexFamilyData(curPlainFamily);
			
			//add family to encrypted scan object
			encScanItem.addFamily(curEncFamily);
			
			//get qualifier set for this family
			NavigableSet<byte[]> curQualifierSet = famMap.get(curPlainFamily);
			
			//check if there is any qualifier
			if(curQualifierSet != null)
			{
				Iterator<byte[]> itrQua = curQualifierSet.iterator();
				
				while(itrQua.hasNext())
				{
					byte[] curQua = itrQua.next();
					
					qualifierSet.add(m_crypter.getIndexQualifierData(curQua));
				}
			}
		}

		FilterList list = new FilterList();
		list.addFilter(new KeyOnlyFilter());
		
		//if there is any qualifier prefix, add it as a filter
		if(qualifierSet.size() > 0)
		{
			byte[][] qualifierPrefixes = new byte[qualifierSet.size()][];
			Iterator<byte[]> itr2 = qualifierSet.iterator();
			int counter = 0;
			while(itr2.hasNext())
			{
				qualifierPrefixes[counter] = itr2.next();
				counter++;
			}
			
			//add filter so that only row keys are received
			list.addFilter(new MultipleColumnPrefixFilter(qualifierPrefixes));
		}
		
		encScanItem.setFilter(list);
		
		//return result scanner in scannerMode1
		return new EncryptedScanner(this, scanItem, m_table.getScanner(encScanItem));
	}

	
	/**
	 * {@inheritDoc}
	 */
	public void put(Put putItem) throws Exception 
	{
		//check inputs
		if(putItem == null)
			throw new IOException("Put item is null");
		
		//get family map from plain text put item
		Map<byte[], List<KeyValue>> familyMap = putItem.getFamilyMap();
		
		//for every family in mapping
		Set<byte[]> keySet = familyMap.keySet();
		Iterator<byte[]> itr = keySet.iterator();
		
		byte[] encRow = null;
		encRow = m_crypter.wrapRow(putItem.getRow(), null, null, 0, null);

		Put newPut = new Put(encRow);
		
		while(itr.hasNext())
		{
			//get entry list for that family
			List<KeyValue> entryList = familyMap.get(itr.next());
			
			//for every entry in a family
			Iterator<KeyValue> entryItr = entryList.iterator();

			//get system time
			long sysTime = System.currentTimeMillis();
			
			while(entryItr.hasNext())
			{
				KeyValue tempItem = entryItr.next();
							
				//wrap family name
				byte[] encFamily = m_crypter.wrapFamily(tempItem);
				
				//wrap value
				byte[] encValue = m_crypter.wrapValue(tempItem);
				
				long encTs;
				byte[] encQualifier;
											
				if(tempItem.getTimestamp() == HConstants.LATEST_TIMESTAMP)
				{						
					//wrap qualifier
					encQualifier = m_crypter.wrapQualifier(tempItem.getRow(), tempItem.getFamily(), tempItem.getQualifier(), sysTime, null);
					
					//wrap time stamp
					encTs = m_crypter.wrapTimestamp(null, null, null, sysTime, null);			
				}
				else
				{						
					//wrap time stamp
					encQualifier = m_crypter.wrapQualifier(tempItem);
					
					//wrap value
					encTs = m_crypter.wrapTimestamp(tempItem);
				}
				
				//add entry to encPutItem
				newPut.add(encFamily, encQualifier, encTs, encValue);
			}
		}
		
		m_table.put(newPut);
	}
}
