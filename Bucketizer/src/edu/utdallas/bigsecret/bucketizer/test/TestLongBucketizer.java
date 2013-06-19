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

package edu.utdallas.bigsecret.bucketizer.test;

import static org.junit.Assert.fail;

import java.util.Arrays;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

import edu.utdallas.bigsecret.bucketizer.LongBucketizer;

public class TestLongBucketizer 
{
public static String bucketizerId = "long1";
	
	@BeforeClass
	public static void testSetup()
	{
		Configuration conf = HBaseConfiguration.create();
		
		try 
		{
			LongBucketizer b = new LongBucketizer(conf, bucketizerId, 0, 1024L * 1024L, 1024 * 64);
			b.createBuckets();
			b.close();
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
	}
	
	@AfterClass
	public static void testCleanup()
	{
		Configuration conf = HBaseConfiguration.create();
		
		try 
		{
			LongBucketizer b = new LongBucketizer(bucketizerId, conf);
			b.removeBuckets();
			b.close();
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
		}
	}
	
	@Test
	public void testBucketExact() throws Exception 
	{
		long input1 = 19;
		
		long input2 = 20;
		
		Configuration conf = HBaseConfiguration.create();
		LongBucketizer b = null;
		
		try 
		{
			b = new LongBucketizer(bucketizerId, conf);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("Bucket could not be created.");
		}
		
		byte[] bucket1 = b.getBucketValue(Bytes.toBytes(input1));
		byte[] bucket2 = b.getBucketValue(Bytes.toBytes(input2));		
	
		System.out.println(bucket1[0] + " " + bucket1[1] + " " + bucket1[2] + " " + bucket1[3]);
		System.out.println(bucket2[0] + " " + bucket2[1] + " " + bucket2[2] + " " + bucket2[3]);
		
		if(!Arrays.equals(bucket1, bucket2))
		{			
			fail("Bucket values should be equal.");
		}
		
		b.close();
	}
	
	@Test
	public void testBucketNext() throws Exception 
	{
		long input1 = 19;
		
		long input2 = 3;
		
		Configuration conf = HBaseConfiguration.create();
		LongBucketizer b = null;
		
		try 
		{
			b = new LongBucketizer(bucketizerId, conf);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("Bucket could not be created.");
		}
		
		byte[] bucket1 = b.getBucketValue(Bytes.toBytes(input1));
		byte[] bucket2 = b.getNextBucketValue(Bytes.toBytes(input2));		
	
		System.out.println(bucket1[0] + " " + bucket1[1] + " " + bucket1[2] + " " + bucket1[3]);
		System.out.println(bucket2[0] + " " + bucket2[1] + " " + bucket2[2] + " " + bucket2[3]);
		
		if(!Arrays.equals(bucket1, bucket2))
		{			
			fail("Bucket values should be equal.");
		}
		
		b.close();
	}
	
	@Test
	public void testBucketPrev() throws Exception 
	{
		long input1 = 19;
		
		long input2 = 3;
		
		Configuration conf = HBaseConfiguration.create();
		LongBucketizer b = null;
		
		try 
		{
			b = new LongBucketizer(bucketizerId, conf);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("Bucket could not be created.");
		}
		
		byte[] bucket1 = b.getPrevBucketValue(Bytes.toBytes(input1));
		byte[] bucket2 = b.getBucketValue(Bytes.toBytes(input2));		
	
		System.out.println(bucket1[0] + " " + bucket1[1] + " " + bucket1[2] + " " + bucket1[3]);
		System.out.println(bucket2[0] + " " + bucket2[1] + " " + bucket2[2] + " " + bucket2[3]);
		
		if(!Arrays.equals(bucket1, bucket2))
		{			
			fail("Bucket values should be equal.");
		}
		
		b.close();
	}
}
