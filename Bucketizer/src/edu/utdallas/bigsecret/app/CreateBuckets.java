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

package edu.utdallas.bigsecret.app;

import java.util.Scanner;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;

import edu.utdallas.bigsecret.bucketizer.ByteBucketizer;
import edu.utdallas.bigsecret.bucketizer.LongBucketizer;

//*****************
//PLAIN BUCKETIZERS
//*****************
//row input bits 16
//row output bits 24
//row id rowBucket1
//qua input bits 16
//qua output bits 24
//qua id quaBucket1
//ts input bits 24
//ts output bits 32
//ts id tsBucket1

public class CreateBuckets 
{
	public static void main(String[] args) throws Exception
	{
		Scanner sc = new Scanner(System.in);
		
		//get bucketizer type
		System.out.println("Enter type of bucketizer: ");
		System.out.println("1 - Byte HBase ");
		System.out.println("2 - Long HBase ");
		int bucketizerType = sc.nextInt();
		
		if(bucketizerType == 1)
		{
			//create configuration
			Configuration conf = HBaseConfiguration.create();
			
			//get zookeeper quorum ip
			System.out.println("Enter zookeeper IP");
			String zookeeperIP = sc.next();
			conf.set("hbase.zookeeper.quorum", zookeeperIP);
			
			//get zookeeper port
			System.out.println("Enter zookeeper Port");
			String zookeeperPort = sc.next();
			conf.set("hbase.zookeeper.property.clientPort", zookeeperPort);
			
			//get b1ucketizer id
			System.out.println("Enter bucketizer id ");
			String id = sc.next();
			
			//get input bit number
			System.out.println("Enter input bit number");
			int inputBits = sc.nextInt();
			
			//create bucketizer and buckets
			ByteBucketizer b = new ByteBucketizer(conf, id, inputBits);
			b.createBuckets();
			b.close();
		}
		else if(bucketizerType == 2)
		{
			//create configuration
			Configuration conf = HBaseConfiguration.create();
			
			//get zookeeper quorum ip
			System.out.println("Enter zookeeper IP");
			String zookeeperIP = sc.next();
			conf.set("hbase.zookeeper.quorum", zookeeperIP);
			
			//get zookeeper port
			System.out.println("Enter zookeeper Port");
			String zookeeperPort = sc.next();
			conf.set("hbase.zookeeper.property.clientPort", zookeeperPort);
			
			//get b1ucketizer id
			System.out.println("Enter bucketizer id ");
			String id = sc.next();
			
			//get bucketizer min value
			System.out.println("Enter min value ");
			long min = sc.nextLong();
			
			//get bucketizer max value
			System.out.println("Enter max value ");
			long max = sc.nextLong();
			
			//get bucketizer number of buckets
			System.out.println("Enter number of buckets ");
			int numberOfBuckets = sc.nextInt();
			
			LongBucketizer b = new LongBucketizer(conf, id, min, max, numberOfBuckets);
			b.createBuckets();
			b.close();
		}
	}
}
