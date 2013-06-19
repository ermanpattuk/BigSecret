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

package edu.utdallas.bigsecret.proxy.test;

import static org.junit.Assert.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
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
import edu.utdallas.bigsecret.proxy.ProxyMode1;

public class TestProxyMode1 
{
	public static String rowBucketizerId = "row1";
	public static String famBucketizerId = "fam1";
	public static String quaBucketizerId = "qua1";
	public static String tsBucketizerId = "ts1";
	public static String tableName = "Proxy1";
	
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
			
			LongBucketizer tsBucketizer = new LongBucketizer(conf, tsBucketizerId, 0, 9223372036854775805L, 1024*64);
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
	public void testAll() throws Exception 
	{
		Configuration confData = HBaseConfiguration.create();
		
		Configuration confBucket = HBaseConfiguration.create();
		
		HBaseBucketizer rowBucketizer = new ByteBucketizer(rowBucketizerId, confBucket);
		HBaseBucketizer famBucketizer = new ByteBucketizer(famBucketizerId, confBucket);
		HBaseBucketizer quaBucketizer = new ByteBucketizer(quaBucketizerId, confBucket);
		HBaseBucketizer tsBucketizer = new LongBucketizer(tsBucketizerId, confBucket);
		Cipher keyCipher = new AesEcb(Bytes.toBytes("1234567890123459"));
		Cipher valCipher = new AesCtr(Bytes.toBytes("1234567890123454"));

		ProxyMode1 proxy = new ProxyMode1(confData, confBucket, rowBucketizer, famBucketizer, quaBucketizer, tsBucketizer, keyCipher, valCipher);
		
		Set<String> families = new HashSet<String>();
		families.add("fam1");
		
		proxy.createTable(tableName, families);
		
		proxy.connect(tableName);
		
		
		//Test Put		
		Put putItem = new Put(Bytes.toBytes("dark knight"));
		putItem.add(Bytes.toBytes("fam1"), Bytes.toBytes("car"), 1001L, Bytes.toBytes("batmobile"));
		putItem.add(Bytes.toBytes("fam1"), Bytes.toBytes("plane"), 1023L, Bytes.toBytes("the bat"));		
		proxy.put(putItem);
		
		Put putItem2 = new Put(Bytes.toBytes("superman"));
		putItem2.add(Bytes.toBytes("fam1"), Bytes.toBytes("car"), 4000L,Bytes.toBytes("himself"));
		putItem2.add(Bytes.toBytes("fam1"), Bytes.toBytes("plane"), 2000L, Bytes.toBytes("himself again"));
		putItem2.add(Bytes.toBytes("fam1"), Bytes.toBytes("girlfriend"), 300L, Bytes.toBytes("none"));	
		putItem2.add(Bytes.toBytes("fam1"), Bytes.toBytes("girlfriend"), 400L, Bytes.toBytes("was it Jane?"));		
		proxy.put(putItem2);

		Put putItem3 = new Put(Bytes.toBytes("neo"));
		putItem3.add(Bytes.toBytes("fam1"), Bytes.toBytes("plane"), 200L, Bytes.toBytes("matrix"));		
		proxy.put(putItem3);

		Put putItem4 = new Put(Bytes.toBytes("aragorn"));
		putItem4.add(Bytes.toBytes("fam1"), Bytes.toBytes("car"), 2300L, Bytes.toBytes("not yet invented"));
		putItem4.add(Bytes.toBytes("fam1"), Bytes.toBytes("girlfriend"), 33220L, Bytes.toBytes("liv tyler"));		
		proxy.put(putItem4);
		
		proxy.flushAll();
		
		//Test Delete
		Delete del = new Delete(Bytes.toBytes("superman"));
		//del.setTimestamp(3000L);
		del.deleteColumns(Bytes.toBytes("fam1"), Bytes.toBytes("girlfriend"), 301L);
		//del.deleteFamily(Bytes.toBytes("fam1"), 1000L);
		
		proxy.delete(del);
		
		proxy.flushAll();
		
		//Test Get
		Get getItem = new Get(Bytes.toBytes("superman"));
		
		Result res = proxy.get(getItem);
	
		System.out.println(Bytes.toString(res.getValue(Bytes.toBytes("fam1"), Bytes.toBytes("car"))));
		System.out.println(Bytes.toString(res.getValue(Bytes.toBytes("fam1"), Bytes.toBytes("plane"))));
		System.out.println(Bytes.toString(res.getValue(Bytes.toBytes("fam1"), Bytes.toBytes("girlfriend"))));
		
		//Test Scan
		Scan sc = new Scan();
		ResultScanner rs = proxy.getScanner(sc);
		
		for(Result res2 = rs.next(); res2 != null; res2 = rs.next())
		{			
			List<KeyValue> list = res2.list();
			
			for(int a = 0; a<list.size(); a++)
			{
				KeyValue temp = list.get(a);
				
				System.out.println("----------");
				System.out.println("row: 		" + Bytes.toString(temp.getRow()));
				System.out.println("family:		" + Bytes.toString(temp.getFamily()));
				System.out.println("qualifier: 	" + Bytes.toString(temp.getQualifier()));
				System.out.println("timestamp:	" + temp.getTimestamp());
				System.out.println("value:		" + Bytes.toString(temp.getValue()));
				System.out.println("----------");
			}
		}
		
		rs.close();
		
		//close proxy
		proxy.close();
		
		//delete current table
		proxy.deleteTable(tableName);
	}

}
