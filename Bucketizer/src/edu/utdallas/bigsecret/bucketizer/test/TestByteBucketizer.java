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

import static org.junit.Assert.*;

import java.util.Arrays;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.junit.BeforeClass;
import org.junit.AfterClass;
import org.junit.Test;

import edu.utdallas.bigsecret.bucketizer.ByteBucketizer;

public class TestByteBucketizer 
{
	public static String bucketizerId = "byte1";
	
	@BeforeClass
	public static void testSetup()
	{
		Configuration conf = HBaseConfiguration.create();
		
		try 
		{
			ByteBucketizer b = new ByteBucketizer(conf, bucketizerId, 16);
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
			ByteBucketizer b = new ByteBucketizer(bucketizerId, conf);
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
		byte[] input1 = new byte[4];
		input1[0] = 10;
		input1[1] = 20;
		input1[2] = 30;
		input1[3] = 40;

		byte[] input2 = new byte[4];
		input2[0] = 10;
		input2[1] = 20;
		input2[2] = 20;
		input2[3] = 50;
		
		Configuration conf = HBaseConfiguration.create();
		ByteBucketizer b = null;
		
		try 
		{
			b = new ByteBucketizer(bucketizerId, conf);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("Bucket could not be created.");
		}
		
		byte[] bucket1 = b.getBucketValue(input1);
		byte[] bucket2 = b.getBucketValue(input2);		
	
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
		byte[] input1 = new byte[4];
		input1[0] = 10;
		input1[1] = 20;
		input1[2] = 30;
		input1[3] = 40;

		byte[] input2 = new byte[4];
		input2[0] = 10;
		input2[1] = 21;
		input2[2] = 20;
		input2[3] = 50;
		
		Configuration conf = HBaseConfiguration.create();
		ByteBucketizer b = null;
		
		try 
		{
			b = new ByteBucketizer(bucketizerId, conf);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("Bucket could not be created.");
		}
		
		byte[] bucket1 = b.getNextBucketValue(input1);
		byte[] bucket2 = b.getBucketValue(input2);

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
		byte[] input1 = new byte[4];
		input1[0] = 10;
		input1[1] = 21;
		input1[2] = 30;
		input1[3] = 40;

		byte[] input2 = new byte[4];
		input2[0] = 10;
		input2[1] = 22;
		input2[2] = 20;
		input2[3] = 50;
		
		Configuration conf = HBaseConfiguration.create();
		ByteBucketizer b = null;
		
		try 
		{
			b = new ByteBucketizer(bucketizerId, conf);
		} 
		catch (Exception e) 
		{
			e.printStackTrace();
			fail("Bucket could not be created.");
		}
		
		byte[] bucket1 = b.getBucketValue(input1);
		byte[] bucket2 = b.getPrevBucketValue(input2);

		System.out.println(bucket1[0] + " " + bucket1[1] + " " + bucket1[2] + " " + bucket1[3]);
		System.out.println(bucket2[0] + " " + bucket2[1] + " " + bucket2[2] + " " + bucket2[3]);
		
		if(!Arrays.equals(bucket1, bucket2))
		{
			fail("Bucket values should be equal.");
		}
		
		b.close();
	}
}
