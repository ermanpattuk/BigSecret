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
package edu.utdallas.bigsecret.crypter;

import org.apache.commons.lang.ArrayUtils;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.util.Bytes;

import edu.utdallas.bigsecret.cipher.Cipher;
import edu.utdallas.bigsecret.hash.Hasher;

/**
 * This crypter is based on Model-3 of the BigSecret paper. <br>
 * It uses Hasher for only row key-parts, and Cipher <br>
 * for the complete Key part and Value part. <br>
 * Here is the wrapping of each key-part <br>
 * row = H(row)<br>
 * fam = 0<br>
 * qua = Ep(row||fam||qua||ts)<br>
 * ts = 2<br>
 * val = Ep(val)
 */
public class CrypterMode3 extends CrypterBase
{
	/**
	 * Hasher for the row-key part.
	 */
	private Hasher m_rowHasher;
	
	/**
	 * Cipher for the whole key.
	 */
	private Cipher m_keyCipher;
	
	/**
	 * Cipher for the value part.
	 */
	private Cipher m_valCipher;

	
	/**
	 * Constructor for this class.
	 * @param rowHasher Hasher for the row key-part.
	 * @param keyCipher Cipher for the whole key-part.
	 * @param valCipher Cipher for the value key-part.
	 * @throws Exception Throws Exception if any of the inputs is null.
	 */
	public CrypterMode3(Hasher rowHasher,
						Cipher keyCipher,
						Cipher valCipher) throws Exception
	{
		if(rowHasher == null)
			throw new Exception("Row Hasher is null");
		else if(valCipher == null)
			throw new Exception("Value cipher is null");
		else if(keyCipher == null)
			throw new Exception("Key cipher is null");
		
		m_rowHasher = rowHasher;
		m_keyCipher = keyCipher;
		m_valCipher = valCipher;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public void close() throws Exception
	{
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getRowHash(byte[] data) throws Exception
	{
		//return row hasher's result
		return m_rowHasher.getHash(data);
	}	
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getIndexRowData(byte[] row) throws Exception 
	{
		//check necessary inputs to this function
		if(row == null || row.length == 0)
			throw new Exception("Row data is null or has no data");
		
		//get bucket data and encode it in Base64.UrlSafe
		byte[] hashData = getRowHash(row);
					
		//return bucket data
		return hashData;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public int getIndexRowDataSize() 
	{
		//return total
		return m_rowHasher.hashSize();
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapRow(KeyValue data) throws Exception 
	{
		//call overloaded function
		return wrapRow(data.getRow(), null, null, 0, null);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapRow(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		//check necessary inputs to this function
		if(row == null || row.length == 0)
			throw new Exception("Row data is null or has no data");
		
		//concatenate bucket output with row cipher's encryption
		return getIndexRowData(row);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapRow(KeyValue data) throws Exception 
	{
		//call overloaded function
		return unwrapRow(null, null, data.getQualifier(), 0, null);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapRow(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier data null or no data");
		
		byte[] completeData = m_keyCipher.decrypt(qualifier);
		
		int rowSize = Bytes.toInt(completeData, 0, 4);
		
		return ArrayUtils.subarray(completeData, 12, 12 + rowSize);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getIndexFamilyData(byte[] family) throws Exception 
	{
		byte[] dummy = Bytes.toBytes("a");
		
		return dummy;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public int getIndexFamilyDataSize() 
	{
		return 1;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapFamily(KeyValue data) throws Exception 
	{
		//call overloaded function
		return wrapFamily(null, null , null, 0, null);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapFamily(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{		
		//just encrypt family data
		return getIndexFamilyData(family);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapFamily(KeyValue data) throws Exception 
	{
		//call overloaded function
		return unwrapFamily(null, null, data.getQualifier(), 0, null);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapFamily(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier data null or no data");
		
		byte[] completeData = m_keyCipher.decrypt(qualifier);
		
		int rowSize = Bytes.toInt(completeData, 0, 4);
		int famSize = Bytes.toInt(completeData, 4, 4);
		
		return ArrayUtils.subarray(completeData, 12+rowSize, 12+rowSize+famSize);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getIndexQualifierData(byte[] qualifier) throws Exception 
	{
		return null;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public int getIndexQualifierDataSize() 
	{
		return 0;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapQualifier(KeyValue data) throws Exception 
	{
		return wrapQualifier(data.getRow(), data.getFamily(), data.getQualifier(), data.getTimestamp(), null);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapQualifier(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(row == null || row.length == 0)
			throw new Exception("Row is null or has no data");
		else if(family == null || family.length == 0)
			throw new Exception("Family is null or has no data");
		else if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier is null or has no data");
		
		byte[] sizeArray = Bytes.toBytes(row.length);
		sizeArray = ArrayUtils.addAll(sizeArray, Bytes.toBytes(family.length));
		sizeArray = ArrayUtils.addAll(sizeArray, Bytes.toBytes(qualifier.length));
		
		byte[] completeData = ArrayUtils.addAll(sizeArray, row);
		completeData = ArrayUtils.addAll(completeData, family);
		completeData = ArrayUtils.addAll(completeData, qualifier);
		completeData = ArrayUtils.addAll(completeData, Bytes.toBytes(ts));
		
		completeData = m_keyCipher.encrypt(completeData);
		
		return completeData;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapQualifier(KeyValue data) throws Exception 
	{
		return unwrapQualifier(null, null, data.getQualifier(), 0, null);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapQualifier(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier data null or no data");
		
		byte[] completeData = m_keyCipher.decrypt(qualifier);
		
		int rowSize = Bytes.toInt(completeData, 0, 4);
		int famSize = Bytes.toInt(completeData, 4, 4);
		int quaSize = Bytes.toInt(completeData, 8, 4);
		
		return ArrayUtils.subarray(completeData, 12+rowSize+famSize, 12+rowSize+famSize+quaSize);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getIndexTimestampData(long timestamp) throws Exception 
	{
		return null;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public int getIndexTimestampDataSize()
	{
		//actually normal size of timestampindex is m_bucketizer.size().
		//but we append bucket value with 0
		//final index data has size 8
		return 0;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public long wrapTimestamp(KeyValue data) throws Exception 
	{
		//call overloaded function
		return wrapTimestamp(null, null, null, 0, null);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public long wrapTimestamp(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{		
		//return long representation of the concatenation
		return 2;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public long unwrapTimestamp(KeyValue data) throws Exception 
	{
		//call overloaded function
		return unwrapTimestamp(null, null, data.getQualifier(), 0, null);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public long unwrapTimestamp(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier data null or no data");
		
		byte[] completeData = m_keyCipher.decrypt(qualifier);
		
		int rowSize = Bytes.toInt(completeData, 0, 4);
		int famSize = Bytes.toInt(completeData, 4, 4);
		int quaSize = Bytes.toInt(completeData, 8, 4);
		
		return Bytes.toLong(ArrayUtils.subarray(completeData, 12+rowSize+famSize+quaSize, 12+rowSize+famSize+quaSize+8));
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] encryptValue(byte[] data) throws Exception
	{
		//return value cipher's result on data
		return m_valCipher.encrypt(data);
	}
		
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] decryptValue(byte[] data) throws Exception
	{
		//return value cipher's result on data
		return m_valCipher.decrypt(data);
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapValue(KeyValue data) throws Exception 
	{
		return wrapValue(null, null, null, 0, data.getValue());
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapValue(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(value == null || value.length == 0)
			throw new Exception("Value is null or has no data");
		
		byte[] encVal = encryptValue(value);
		
		return encVal;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapValue(KeyValue data) throws Exception 
	{
		return unwrapValue(null, null, null, 0, data.getValue());
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapValue(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(value == null || value.length == 0)
			throw new Exception("Value is null or has no data");
		
		return decryptValue(value);
	}
}
