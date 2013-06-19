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


import java.util.HashSet;
import java.util.Set;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Test;

import edu.utdallas.bigsecret.cipher.AesCtr;
import edu.utdallas.bigsecret.cipher.AesEcb;
import edu.utdallas.bigsecret.cipher.Cipher;
import edu.utdallas.bigsecret.hash.Hasher;
import edu.utdallas.bigsecret.hash.Sha256;
import edu.utdallas.bigsecret.proxy.ProxyMode2;

public class TestProxyMode2 
{
	public static String tableName = "Proxy2";

	@Test
	public void testAll() throws Exception 
	{
		Configuration confData = HBaseConfiguration.create();
		
		Configuration confBucket = HBaseConfiguration.create();
		
		Hasher rowHasher = new Sha256(Bytes.toBytes("123"), 4);
		Hasher famHasher = new Sha256(Bytes.toBytes("123"), 4);
		Hasher quaHasher = new Sha256(Bytes.toBytes("123"), 4);
		Hasher tsHasher = new Sha256(Bytes.toBytes("123"), 7);
		Cipher keyCipher = new AesEcb(Bytes.toBytes("1234567890123459"));
		Cipher valCipher = new AesCtr(Bytes.toBytes("1234567890123454"));

		ProxyMode2 proxy = new ProxyMode2(confData, confBucket, rowHasher, famHasher, quaHasher, tsHasher, keyCipher, valCipher);
		
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
		del.deleteColumn(Bytes.toBytes("fam1"), Bytes.toBytes("girlfriend"), 400L);
		
		proxy.delete(del);
		
		proxy.flushAll();
		
		//Test Get
		Get getItem = new Get(Bytes.toBytes("superman"));
		
		Result res = proxy.get(getItem);
	
		System.out.println(Bytes.toString(res.getValue(Bytes.toBytes("fam1"), Bytes.toBytes("car"))));
		System.out.println(Bytes.toString(res.getValue(Bytes.toBytes("fam1"), Bytes.toBytes("plane"))));
		System.out.println(Bytes.toString(res.getValue(Bytes.toBytes("fam1"), Bytes.toBytes("girlfriend"))));
				
		//close proxy
		proxy.close();
		
		//delete current table
		proxy.deleteTable(tableName);
	}
}
