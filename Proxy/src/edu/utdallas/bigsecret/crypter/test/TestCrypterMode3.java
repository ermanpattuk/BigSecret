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

package edu.utdallas.bigsecret.crypter.test;

import static org.junit.Assert.*;

import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Test;

import edu.utdallas.bigsecret.cipher.AesCtr;
import edu.utdallas.bigsecret.cipher.Cipher;
import edu.utdallas.bigsecret.crypter.CrypterBase;
import edu.utdallas.bigsecret.crypter.CrypterMode3;
import edu.utdallas.bigsecret.hash.Hasher;
import edu.utdallas.bigsecret.hash.Sha256;

public class TestCrypterMode3 
{
	@Test
	public void testAll() 
	{
		try
		{
			Hasher rowHasher = new Sha256(Bytes.toBytes("1234"));
			Cipher keyCipher = new AesCtr(Bytes.toBytes("1234567890123459"));
			Cipher valCipher = new AesCtr(Bytes.toBytes("1234567890123454"));
			
			CrypterBase cr = new CrypterMode3(rowHasher, keyCipher, valCipher);
			
			String rowData = "12341";
			String familyData = "fam123";
			String qualifierData = "qua161";
			long timestampData = 100;
			long valueData = 100689;
			
			byte[] row = Bytes.toBytes(rowData);
			byte[] family = Bytes.toBytes(familyData);
			byte[] qualifier = Bytes.toBytes(qualifierData);
			byte[] value = Bytes.toBytes(valueData);
			
			KeyValue testItem = new KeyValue(row, family, qualifier, timestampData, value);
			
			KeyValue encItem = new KeyValue(cr.wrapRow(testItem),
											cr.wrapFamily(testItem),
											cr.wrapQualifier(testItem),
											cr.wrapTimestamp(testItem),
											cr.wrapValue(testItem));
			
			String decRow = Bytes.toString(cr.unwrapRow(encItem));
			String decFam = Bytes.toString(cr.unwrapFamily(encItem));
			String decQua = Bytes.toString(cr.unwrapQualifier(encItem));
			long decTs = cr.unwrapTimestamp(encItem);
			long decVal = Bytes.toLong(cr.unwrapValue(encItem));
			
			if(!rowData.equals(decRow))
			{
				fail("row-keys are not equal");
			}
			else if(!familyData.equals(decFam))
			{
				fail("families are not equal");
			}
			else if(!qualifierData.equals(decQua))
			{
				fail("qualifiers are not equal");
			}
			else if(timestampData != decTs)
			{
				fail("timestamps are not equal");
			}
			else if(valueData != decVal)
			{
				fail("values are not equal");
			}
			
			cr.close();
		}
		catch (Exception e)
		{
			e.printStackTrace();
			fail("Test failed");
		}	
	}
}
