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

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.ArrayUtils;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.util.Bytes;

import edu.utdallas.bigsecret.bucketizer.HBaseBucketizer;
import edu.utdallas.bigsecret.cipher.Cipher;
import edu.utdallas.bigsecret.util.Utilities;

/**
 * This crypter is based on Model-1 of the BigSecret paper. <br>
 * It uses Bucketizer for the first four key-parts, and Cipher <br>
 * for the complete Key part and Value part. <br>
 * Here is the wrapping of each key-part <br>
 * row = B(row)<br>
 * fam = B(fam)<br>
 * qua = B(qua) || Ed(row||fam||qua||ts)<br>
 * ts = B(ts) <br>
 * val = Ep(val) <br>
 */
public class CrypterMode1 extends CrypterBase
{
	/**
	 * Bucketizer for row.
	 */
	private HBaseBucketizer m_rowBucketizer;
	
	/**
	 * Bucketizer for family.
	 */
	private HBaseBucketizer m_famBucketizer;
	
	/**
	 * Bucketizer for qualifier.
	 */
	private HBaseBucketizer m_quaBucketizer;
	
	/**
	 * Bucketizer for timestamp.
	 */
	private HBaseBucketizer m_tsBucketizer;
	
	/**
	 * Cipher for the complete Key part.
	 */
	private Cipher m_keyCipher;
	
	/**
	 * Cipher for value.
	 */
	private Cipher m_valCipher;
	
	
	/**
	 * Constructor for this class. 
	 * @param rowBucketizer Bucketizer for row key-part.
	 * @param famBucketizer Bucketizer for family key-part.
	 * @param quaBucketizer Bucketizer for qualifier key-part.
	 * @param tsBucketizer Bucketizer for timestamp key-part.
	 * @param keyCipher Cipher for the whole Key.
	 * @param valCipher Cipher for value part.
	 * @throws Exception Throws exception if one of the parameters is null.
	 */
	public CrypterMode1(HBaseBucketizer rowBucketizer,
						HBaseBucketizer famBucketizer,
						HBaseBucketizer quaBucketizer,
						HBaseBucketizer tsBucketizer,
						Cipher keyCipher,
						Cipher valCipher) throws Exception
	{
		//check inputs
		if(rowBucketizer == null)
			throw new Exception("Row bucketizer is null");
		else if(famBucketizer == null)
			throw new Exception("Family bucketizer is null");
		else if(quaBucketizer == null)
			throw new Exception("Qualifier bucketizer is null");
		else if(tsBucketizer == null)
			throw new Exception("Timestamp bucketizer is null");
		else if(valCipher == null)
			throw new Exception("Value cipher is null");
		else if(keyCipher == null)
			throw new Exception("Key cipher is null");
		
		m_rowBucketizer = rowBucketizer;
		m_famBucketizer = famBucketizer;
		m_quaBucketizer = quaBucketizer;
		m_tsBucketizer = tsBucketizer;
		m_keyCipher = keyCipher;
		m_valCipher = valCipher;
	}
	
	
	/**
	 * Closes bucketizers. This functions needs to be called once everything is finished.
	 */
	public void close() throws Exception
	{
		m_rowBucketizer.close();
		m_famBucketizer.close();
		m_quaBucketizer.close();
		m_tsBucketizer.close();
	}
		
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getRowBucket(byte[] data) throws Exception
	{
		//return bucket value for the row data
		return m_rowBucketizer.getBucketValue(data);
	}	

	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getRowNextBucket(byte[] data) throws Exception
	{
		//return next bucket value for the row data
		return m_rowBucketizer.getNextBucketValue(data);
	}

	
	/**
	 * Returns the bucket value of the row key-part.
	 * @param row Input data
	 * @throws Throws exception if input data is empty or null.
	 */
	public byte[] getIndexRowData(byte[] row) throws Exception 
	{
		//check necessary inputs to this function
		if(row == null || row.length == 0)
			throw new Exception("Row data is null or has no data");
		
		//get bucket data
		byte[] bucketData = getRowBucket(row);
					
		//return bucket data
		return bucketData;
	}

	
	/**
	 * Returns size of a bucket value for the bucketizer.
	 */
	public int getIndexRowDataSize() 
	{
		//learn bucket output size of rowBucketizer
		int bucketOutputSize = m_rowBucketizer.getBucketValueSize();
		
		//return total
		return bucketOutputSize;
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
	public byte[] wrapRow(byte[] row, byte[] family, byte[] qualifier, long ts,	byte[] value) throws Exception 
	{
		//check necessary inputs to this function
		if(row == null || row.length == 0)
			throw new Exception("Row data is null or has no data");
		
		//concatenate bucket
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
		
		int qualifierIndexSize = getIndexQualifierDataSize();
		byte[] completeData = m_keyCipher.decrypt(qualifier, qualifierIndexSize);
		
		int rowSize = Bytes.toInt(completeData, 0, 4);
		
		return ArrayUtils.subarray(completeData, 12, 12 + rowSize);
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] getFamilyBucket(byte[] data) throws Exception
	{
		//return bucket value for the row data
		return m_famBucketizer.getBucketValue(data);
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] getIndexFamilyData(byte[] family) throws Exception 
	{
		if(family == null || family.length == 0)
			throw new Exception("Family is null or has no data");
		
		byte[] famBucketData = Base64.encodeBase64URLSafe(m_famBucketizer.getBucketValue(family));
		
		return famBucketData;
	}
	

	/**
	 * {@inheritDoc}
	 */
	public int getIndexFamilyDataSize() 
	{
		int bucketSize = m_famBucketizer.getBucketValueSize();
		
		//base64 conversion
		return ((bucketSize*8)+5)/6;
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapFamily(KeyValue data) throws Exception 
	{
		return wrapFamily(null, data.getFamily(), null, 0, null);
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] wrapFamily(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(family == null || family.length == 0)
			throw new Exception("Family is null or has no data");
		
		byte[] indexData = getIndexFamilyData(family);
		
		return indexData;
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapFamily(KeyValue data) throws Exception 
	{
		return unwrapFamily(null, null, data.getQualifier(), 0, null);
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] unwrapFamily(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier data null or no data");
		
		int qualifierIndexSize = getIndexQualifierDataSize();
		byte[] completeData = m_keyCipher.decrypt(qualifier, qualifierIndexSize);
		
		int rowSize = Bytes.toInt(completeData, 0, 4);
		int famSize = Bytes.toInt(completeData, 4, 4);
		
		return ArrayUtils.subarray(completeData, 12+rowSize, 12+rowSize+famSize);
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] getQualifierBucket(byte[] data) throws Exception
	{
		//return bucket value for the qualifier data
		return m_quaBucketizer.getBucketValue(data);
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] getQualifierNextBucket(byte[] data) throws Exception
	{
		//return next bucket value for the qua data
		return m_quaBucketizer.getNextBucketValue(data);
	}
	

	/**
	 * {@inheritDoc}
	 */
	public byte[] getIndexQualifierData(byte[] qualifier) throws Exception 
	{
		//check necessary inputs to this function
		if(qualifier == null || qualifier.length == 0)
			throw new Exception("Qualifier data is null or has no data");
		
		//get bucket data
		byte[] bucketValue = getQualifierBucket(qualifier);
		
		//return bucket value
		return bucketValue;
	}
	

	/**
	 * {@inheritDoc}
	 */
	public int getIndexQualifierDataSize() 
	{
		//learn bucket output size of quaBucketizer
		int bucketOutputSize = m_quaBucketizer.getBucketValueSize();
		
		//return total value
		return bucketOutputSize;
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
		
		byte[] qualifierIndex = getIndexQualifierData(qualifier);
		
		byte[] sizeArray = Bytes.toBytes(row.length);
		sizeArray = ArrayUtils.addAll(sizeArray, Bytes.toBytes(family.length));
		sizeArray = ArrayUtils.addAll(sizeArray, Bytes.toBytes(qualifier.length));
		
		byte[] completeData = ArrayUtils.addAll(sizeArray, row);
		completeData = ArrayUtils.addAll(completeData, family);
		completeData = ArrayUtils.addAll(completeData, qualifier);
		completeData = ArrayUtils.addAll(completeData, Bytes.toBytes(ts));
		
		completeData = m_keyCipher.encrypt(completeData);
		
		return ArrayUtils.addAll(qualifierIndex, completeData);
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
		
		int qualifierIndexSize = getIndexQualifierDataSize();
		byte[] completeData = m_keyCipher.decrypt(qualifier, qualifierIndexSize);
		
		int rowSize = Bytes.toInt(completeData, 0, 4);
		int famSize = Bytes.toInt(completeData, 4, 4);
		int quaSize = Bytes.toInt(completeData, 8, 4);
		
		return ArrayUtils.subarray(completeData, 12+rowSize+famSize, 12+rowSize+famSize+quaSize);
	}	


	/**
	 * {@inheritDoc}
	 */
	public byte[] getTimestampBucket(long data) throws Exception
	{
		//get bucket value for data
		byte[] bucketValue = m_tsBucketizer.getBucketValue(Bytes.toBytes(data));
		
		return bucketValue;
	}
	
	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getTimestampNextBucket(long data) throws Exception
	{
		//get bucket value for data
		byte[] bucketValue = m_tsBucketizer.getNextBucketValue(Bytes.toBytes(data));
		
		return bucketValue;
	}

	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getTimestampPrevBucket(long data) throws Exception
	{
		//get bucket value for data
		byte[] bucketValue = m_tsBucketizer.getPrevBucketValue(Bytes.toBytes(data));
		
		return bucketValue;
	}

	
	/**
	 * {@inheritDoc}
	 */
	public byte[] getIndexTimestampData(long timestamp) throws Exception 
	{
		//get bucket result
		return m_tsBucketizer.getBucketValue(Bytes.toBytes(timestamp));
	}

	
	/**
	 * {@inheritDoc}
	 */
	public int getIndexTimestampDataSize() 
	{
		return 0;
	}

	
	/**
	 * {@inheritDoc}
	 */
	public long wrapTimestamp(KeyValue data) throws Exception 
	{
		//call overloaded function
		return wrapTimestamp(null, null, null, data.getTimestamp(), null);
	}

	
	/**
	 * {@inheritDoc}
	 */
	public long wrapTimestamp(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception 
	{
		//get bucket result
		byte[] tsBucketResult = m_tsBucketizer.getBucketValue(Bytes.toBytes(ts));
		
		//return long representation of the concatenation
		return Utilities.getLong(tsBucketResult);
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
		
		int qualifierIndexSize = getIndexQualifierDataSize();
		byte[] completeData = m_keyCipher.decrypt(qualifier, qualifierIndexSize);
		
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
