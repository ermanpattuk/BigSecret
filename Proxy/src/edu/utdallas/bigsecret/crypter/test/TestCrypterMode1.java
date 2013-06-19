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

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.utdallas.bigsecret.bucketizer.ByteBucketizer;
import edu.utdallas.bigsecret.bucketizer.HBaseBucketizer;
import edu.utdallas.bigsecret.bucketizer.LongBucketizer;
import edu.utdallas.bigsecret.cipher.AesCtr;
import edu.utdallas.bigsecret.cipher.AesEcb;
import edu.utdallas.bigsecret.cipher.Cipher;
import edu.utdallas.bigsecret.crypter.CrypterBase;
import edu.utdallas.bigsecret.crypter.CrypterMode1;

public class TestCrypterMode1 
{
	public static String rowBucketizerId = "row1";
	public static String famBucketizerId = "fam1";
	public static String quaBucketizerId = "qua1";
	public static String tsBucketizerId = "ts1";
	
	@BeforeClass
	public static void testSetup()
	{
		Configuration conf = HBaseConfiguration.create();
		
		try 
		{
			ByteBucketizer rowBucketizer = new ByteBucketizer(conf, rowBucketizerId, 8);
			rowBucketizer.createBuckets();
			rowBucketizer.close();
			
			ByteBucketizer famBucketizer = new ByteBucketizer(conf, famBucketizerId, 8);
			famBucketizer.createBuckets();
			famBucketizer.close();
			
			ByteBucketizer quaBucketizer = new ByteBucketizer(conf, quaBucketizerId, 8);
			quaBucketizer.createBuckets();
			quaBucketizer.close();
			
			LongBucketizer tsBucketizer = new LongBucketizer(conf, tsBucketizerId, 0, 1024*1024, 1024);
			tsBucketizer.createBuckets();
			tsBucketizer.close();
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("Test failed.");
		}
	}
	
	@AfterClass
	public static void testCleanUp()
	{
		Configuration conf = HBaseConfiguration.create();
		
		try 
		{
			ByteBucketizer rowBucketizer = new ByteBucketizer(rowBucketizerId, conf);
			rowBucketizer.removeBuckets();
			rowBucketizer.close();
			
			ByteBucketizer famBucketizer = new ByteBucketizer(famBucketizerId, conf);
			famBucketizer.removeBuckets();
			famBucketizer.close();
			
			ByteBucketizer quaBucketizer = new ByteBucketizer(quaBucketizerId, conf);
			quaBucketizer.removeBuckets();
			quaBucketizer.close();
			
			LongBucketizer tsBucketizer = new LongBucketizer(tsBucketizerId, conf);
			tsBucketizer.removeBuckets();
			tsBucketizer.close();
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("Test failed.");
		}
	}

	@Test
	public void testAll() 
	{
		try
		{
			Configuration conf = HBaseConfiguration.create();
			
			HBaseBucketizer rowBucketizer = new ByteBucketizer(rowBucketizerId, conf);
			HBaseBucketizer famBucketizer = new ByteBucketizer(famBucketizerId, conf);
			HBaseBucketizer quaBucketizer = new ByteBucketizer(quaBucketizerId, conf);
			HBaseBucketizer tsBucketizer = new LongBucketizer(tsBucketizerId, conf);
			Cipher keyCipher = new AesEcb(Bytes.toBytes("1234567890123454"));
			Cipher valCipher = new AesCtr(Bytes.toBytes("1234567890123454"));
			
			
			CrypterBase cr = new CrypterMode1(rowBucketizer, famBucketizer, quaBucketizer, tsBucketizer, keyCipher, valCipher);
			
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
			fail("Not yet implemented");			
		}	
	}

}
