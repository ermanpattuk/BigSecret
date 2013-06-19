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

import org.apache.hadoop.hbase.KeyValue;


/**
 * This class is responsible for data encryption, decryption, hashing, bucketiation, and wrapping<br>
 * up (i.e., combining several of those in specified ways). 
 */
public abstract class CrypterBase
{
	/**
	 * Class constructor
	 */
	public CrypterBase()
	{		
	}
	
	
	/**
	 * Close this crypter. Any other object that needs to be closed down should be close in this function.
	 * @throws Exception
	 */
	public abstract void close() throws Exception;
	
	
	/**
	 * Get row bucket value for the given data.
	 * @param data Input data in ASCII encoding
	 * @return Bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getRowBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get next row bucket value for the given data
	 * @param data Input data in ASCII encoding
	 * @return Next bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getRowNextBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get previous row bucket value for the given data
	 * @param data Input data in ASCII encoding
	 * @return Previous bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getRowPrevBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get hash value of the input data with row key
	 * @param data Input data in ASCII encoding
	 * @return Hash value in ASCII encoding
	 * @throws Exception
	 */
	public byte[] getRowHash(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Encrypt data with row key
	 * @param data Input data in ASCII encoding
	 * @return Encrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] encryptRow(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt input data with row key
	 * @param data Input data in ASCII encoding
	 * @return Decrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] decryptRow(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt input data starting from offset
	 * @param data Input data in ASCII encoding
	 * @param offset Offset in the input data
	 * @return Decrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] decryptRow(byte[] data, int offset) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get auxiliary data for row, that is appended to the start of wrapped row data
	 * @param row Row data in ASCII encoding
	 * @return Auxiliary data in Base64.UrlSafe encoding
	 */
	public abstract byte[] getIndexRowData(byte[] row) throws Exception;
	
	
	/**
	 * Returns size of the auxiliary row data
	 * @return
	 */
	public abstract int getIndexRowDataSize();
	
	
	/**
	 * Wrap data depending on how system is implemented
	 * @param data Input KeyValue data
	 * @return Wrapped row data
	 * @throws Exception
	 */
	public abstract byte[] wrapRow(KeyValue data) throws Exception;
	
	
	/**
	 * Wrap data depending on how system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Wrapped row data
	 * @throws Exception
	 */
	public abstract byte[] wrapRow(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Unwrap data depending on how system is implemented
	 * @param data Input KeyValue data
	 * @return Unwrapped data
	 * @throws Exception
	 */
	public abstract byte[] unwrapRow(KeyValue data) throws Exception;
	
	
	/**
	 * Unwrap data depending on how system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Unwrapped data
	 * @throws Exception
	 */
	public abstract byte[] unwrapRow(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Get family bucket value for the given data
	 * @param data Input data in ASCII encoding
	 * @return Bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getFamilyBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get next family bucket value for the given data
	 * @param data Input data in ASCII encoding
	 * @return Next bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getFamilyNextBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get previous bucket value for the given data
	 * @param data Input data in ASCII encoding
	 * @return Previous bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getFamilyPrevBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get hash value for the input data with family key
	 * @param data Input data in ASCII encoding
	 * @return Hash value in ASCII encoding
	 * @throws Exception
	 */
	public byte[] getFamilyHash(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Encrypt data with family key
	 * @param data Input data in ASCII encoding
	 * @return Encrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] encryptFamily(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt data with family key
	 * @param data Input data in ASCII encoding
	 * @return Decrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] decryptFamily(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt data with family key starting from offset
	 * @param data Input data in ASCII encoding
	 * @param offset Offset
	 * @return Decrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] decryptFamily(byte[] data, int offset) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get auxiliary data for family, that is appended to the start of wrapped family data
	 * @param family Family data in ASCII encoding
	 * @return Auxiliary data in Base64.UrlSafe encoding
	 */
	public abstract byte[] getIndexFamilyData(byte[] family) throws Exception;
	
	
	/**
	 * Returns size of the auxiliary family data
	 * @return
	 */
	public abstract int getIndexFamilyDataSize();
	
	
	/**
	 * Wrap family depending on how the system is implemented
	 * @param data Input KeyValue data
	 * @return Wrapped family
	 * @throws Exception
	 */
	public abstract byte[] wrapFamily(KeyValue data) throws Exception;
	
	
	/**
	 * Wrap family depending on how the system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Wrapped family
	 * @throws Exception
	 */
	public abstract byte[] wrapFamily(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Unwrap family depending on how the system is implemented
	 * @param data Input KeyValue data
	 * @return Unwrapped family
	 * @throws Exception
	 */
	public abstract byte[] unwrapFamily(KeyValue data) throws Exception;
	
	
	/**
	 * Unwrap family depending on how the system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Unwrapped family
	 * @throws Exception
	 */
	public abstract byte[] unwrapFamily(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Get qualifier bucket value for input data
	 * @param data Input data in ASCII encoding
	 * @return Bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getQualifierBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get next qualifier bucket value for input data
	 * @param data Input data in ASCII encoding
	 * @return Next bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getQualifierNextBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get previous qualifier bucket value for input data
	 * @param data Input data in ASCII encoding
	 * @return Previous bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getQualifierPrevBucket(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get hash value for input data with qualifier key
	 * @param data Input data in ASCII encoding
	 * @return Hash value in ASCII encoding
	 * @throws Exception
	 */
	public byte[] getQualifierHash(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Encrypt input data with qualifier key
	 * @param data Input data in ASCII encoding
	 * @return Encrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] encryptQualifier(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt input data with qualifier key
	 * @param data Input data in ASCII encoding
	 * @return Decrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] decryptQualifier(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt input data with qualifier key starting from offset 
	 * @param data Input data in ASCII encoding
	 * @param offset Offset
	 * @return Decrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] decryptQualifier(byte[] data, int offset) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get auxiliary data for qualifier, that is appended to the start of wrapped qualifier data
	 * @param qualifier Qualifier data in ASCII encoding
	 * @return Auxiliary data in Base64.UrlSafe encoding
	 */
	public abstract byte[] getIndexQualifierData(byte[] qualifier) throws Exception;
	
	
	/**
	 * Returns size of the auxiliary qualifier data
	 * @return
	 */
	public abstract int getIndexQualifierDataSize();
	
	/**
	 * Wrap qualifier depending on how system is implemented
	 * @param data Input KeyValue data
	 * @return Wrapped qualifier
	 * @throws Exception
	 */
	public abstract byte[] wrapQualifier(KeyValue data) throws Exception;

	
	/**
	 * Wrap qualifier depending on how system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Wrapped qualifier
	 * @throws Exception
	 */
	public abstract byte[] wrapQualifier(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Unwrap qualifier depending on how system is implemented
	 * @param data Input KeyValue data
	 * @return Unwrapped qualifier
	 * @throws Exception
	 */
	public abstract byte[] unwrapQualifier(KeyValue data) throws Exception;

	
	/**
	 * Unwrap qualifier depending on how system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Unwrapped qualifier
	 * @throws Exception
	 */
	public abstract byte[] unwrapQualifier(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Get timestamp bucket value for the input data
	 * @param data Input data
	 * @return Bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getTimestampBucket(long data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get next timestamp bucket value for input data
	 * @param data Input data
	 * @return Next bucket value if exists in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getTimestampNextBucket(long data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get previous timestamp bucket value for input data
	 * @param data Input data
	 * @return Previous bucket value if exist in ASCII encoding, null otherwise
	 * @throws Exception
	 */
	public byte[] getTimestampPrevBucket(long data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Get hash value of input data with timestamp key
	 * @param data Input data
	 * @return Hash value in ASCII encoding
	 * @throws Exception
	 */
	public byte[] getTimestampHash(long data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Encrypt input data with timestamp key
	 * @param data Input data
	 * @return Encrypted data in ASCII encoding
	 * @throws Exception
	 */
	public byte[] encryptTimestamp(long data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt input data with timestamp key
	 * @param data Input data in ASCII encoding
	 * @return Decrypted data
	 * @throws Exception
	 */
	public long decryptTimestamp(byte[] data) throws Exception
	{
		return 0;
	}
	
	
	/**
	 * Get auxiliary data for timestamp, that is appended to the start of wrapped qualifier data
	 * @param qualifier Qualifier data in ASCII encoding
	 * @return Auxiliary data in Base64.UrlSafe encoding
	 */
	public abstract byte[] getIndexTimestampData(long timestamp) throws Exception;
	
	
	/**
	 * Returns size of the auxiliary qualifier data
	 * @return
	 */
	public abstract int getIndexTimestampDataSize();
	
	
	/**
	 * Wrap tiemstamp depending on how system is implemented
	 * @param data Input KeyValue data
	 * @return Wrapped timestamp
	 * @throws Exception
	 */
	public abstract long wrapTimestamp(KeyValue data) throws Exception;
	
	
	/**
	 * Wrap timestamp depending on how system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Wrapped timestamp
	 * @throws Exception
	 */
	public abstract long wrapTimestamp(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Unwrap timestamp depending on how system is implemented
	 * @param data Input KeyValue data
	 * @return unwrapped timestamp
	 * @throws Exception
	 */
	public abstract long unwrapTimestamp(KeyValue data) throws Exception;
	
	
	/**
	 * Unwrap timestamp depending on how system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Unwrapped timestamp
	 * @throws Exception
	 */
	public abstract long unwrapTimestamp(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Encrypt input data with value key
	 * @param data Input data
	 * @return Encrypted data
	 * @throws Exception
	 */
	public byte[] encryptValue(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt input data with value key
	 * @param data Input data
	 * @return Decrypted data
	 * @throws Exception
	 */
	public byte[] decryptValue(byte[] data) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Decrypt input data with value key starting from offset
	 * @param data Input data
	 * @param offset Offset
	 * @return Decrypted data
	 * @throws Exception
	 */
	public byte[] decryptValue(byte[] data, int offset) throws Exception
	{
		return null;
	}
	
	
	/**
	 * Wrap value depending on how system is implemented
	 * @param data Input KeyValue data
	 * @return Wrapped value
	 * @throws Exception
	 */
	public abstract byte[] wrapValue(KeyValue data) throws Exception;
	
	
	/**
	 * Wrap value depending on how system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Wrapped value
	 * @throws Exception
	 */
	public abstract byte[] wrapValue(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
	
	
	/**
	 * Unwrap value depending on how system is implemented
	 * @param data Input KeyValue data
	 * @return Unwrapped value
	 * @throws Exception
	 */
	public abstract byte[] unwrapValue(KeyValue data) throws Exception;
	
	
	/**
	 * Unwrap value depending on how system is implemented
	 * @param row Row data
	 * @param family Family data
	 * @param qualifier Qualifier data
	 * @param ts Timestamp data
	 * @param value Value data
	 * @return Unwrapped value
	 * @throws Exception
	 */
	public abstract byte[] unwrapValue(byte[] row, byte[] family, byte[] qualifier, long ts, byte[] value) throws Exception;
}
