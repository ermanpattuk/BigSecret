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

package client;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Vector;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.util.Bytes;

import com.yahoo.ycsb.ByteArrayByteIterator;
import com.yahoo.ycsb.ByteIterator;
import com.yahoo.ycsb.DB;
import com.yahoo.ycsb.DBException;

import edu.utdallas.bigsecret.bucketizer.ByteBucketizer;
import edu.utdallas.bigsecret.bucketizer.HBaseBucketizer;
import edu.utdallas.bigsecret.bucketizer.LongBucketizer;
import edu.utdallas.bigsecret.cipher.AesCtr;
import edu.utdallas.bigsecret.cipher.AesEcb;
import edu.utdallas.bigsecret.cipher.Cipher;
import edu.utdallas.bigsecret.hash.Hasher;
import edu.utdallas.bigsecret.hash.Sha256;
import edu.utdallas.bigsecret.proxy.ProxyBase;
import edu.utdallas.bigsecret.proxy.ProxyMode1;
import edu.utdallas.bigsecret.proxy.ProxyMode2;
import edu.utdallas.bigsecret.proxy.ProxyMode3;


/**
 * ATTENTION!!! CREATE BUCKETS BEFORE.
 */
public class BigSecretClient extends DB
{
	protected String m_tableName;
	protected byte[] m_familyName;
	protected ProxyBase m_proxy;
	protected int m_proxyMode;

    public static final int Ok=0;
    public static final int ServerError=-1;
    public static final int HttpError=-2;
    public static final int NoMatchingRecord=-3;
    
    
    /**
     * proxy mode 1 = bucket
     * proxy mode 2 = hash
     * proxy mode 3 = proof mode
     */
    public ProxyBase getProxy(int mode, Configuration confData, Configuration confBucket) throws Exception
    {
    	if(mode == 1)
    	{
    		HBaseBucketizer rowBucketizer = new LongBucketizer("rowLong1", confBucket);
    		HBaseBucketizer famBucketizer = new ByteBucketizer("famByte1", confBucket);
    		HBaseBucketizer quaBucketizer = new ByteBucketizer("quaByte1", confBucket);
    		HBaseBucketizer tsBucketizer = new LongBucketizer("tsLong1", confBucket);
    		Cipher keyCipher = new AesEcb(Bytes.toBytes("1234567890123459"));
    		Cipher valCipher = new AesCtr(Bytes.toBytes("1234567890123454"));
    		
    		rowBucketizer.fillCache();
    		
    		return new ProxyMode1(confData, confBucket, rowBucketizer, famBucketizer, quaBucketizer, tsBucketizer, keyCipher, valCipher);
    	}
    	else if(mode == 2)
    	{
    		Hasher rowHasher = new Sha256(Bytes.toBytes("123"));
    		Hasher famHasher = new Sha256(Bytes.toBytes("123"));
    		Hasher quaHasher = new Sha256(Bytes.toBytes("123"));
    		Hasher tsHasher = new Sha256(Bytes.toBytes("123"), 7);
    		Cipher keyCipher = new AesEcb(Bytes.toBytes("1234567890123459"));
    		Cipher valCipher = new AesEcb(Bytes.toBytes("1234567890123454"));

    		return new ProxyMode2(confData, confBucket, rowHasher, famHasher, quaHasher, tsHasher, keyCipher, valCipher);
    	}
    	else if(mode == 3)
    	{
    		Hasher rowHasher = new Sha256(Bytes.toBytes("123"));
    		Cipher keyCipher = new AesEcb(Bytes.toBytes("1234567890123459"));
    		Cipher valCipher = new AesEcb(Bytes.toBytes("1234567890123454"));
    		
    		return new ProxyMode3(confData, confBucket, rowHasher, keyCipher, valCipher);
    	}
    	else
    	{
    		return null;
    	}
    }
	
	public void cleanup() throws DBException
	{
		try
		{
			m_proxy.close();
		}
		catch (Exception e)
		{
			throw new DBException(e);
		}
	}
	
	public void init() throws DBException
	{
		//set column family
		String familyName = getProperties().getProperty("columnFamily");
		if(familyName == null)
		{
			throw new DBException("No column family specified");
		}
		else
		{
			m_familyName = Bytes.toBytes(familyName);
		}
		
		//create table variables
		Set<String> families = new HashSet<String>();
		families.add(familyName);
		
		//set data server conf object		
		Configuration confData = HBaseConfiguration.create();
		String dataServerIP = getProperties().getProperty("dataServerIP");
		if(dataServerIP == null)
		{
			throw new DBException("No data server IP is specified");
		}
		else
		{
			confData.set("hbase.zookeeper.quorum", dataServerIP);
		}
		String dataServerPort = getProperties().getProperty("dataServerPort");
		if(dataServerPort == null)
		{
			throw new DBException("No data server port is specified");
		}
		else
		{
			confData.set("hbase.zookeeper.property.clientPort", dataServerPort);	
		}		
		
		//set bucket server conf object
		Configuration confBucket = HBaseConfiguration.create();
		String bucketServerIP = getProperties().getProperty("bucketServerIP");
		if(bucketServerIP == null)
		{
			throw new DBException("No bucket server IP is specified");
		}
		else
		{
			confBucket.set("hbase.zookeeper.quorum", bucketServerIP);
		}
		String bucketServerPort = getProperties().getProperty("bucketServerPort");
		if(bucketServerPort == null)
		{
			throw new DBException("No bucket server port is specified");
		}
		else
		{
			confBucket.set("hbase.zookeeper.property.clientPort", bucketServerPort);	
		}
		
		m_tableName = getProperties().getProperty("tableName");
		if(m_tableName == null)
		{
			throw new DBException("Table name is not specified");
		}
		
		//set proxy mode
		String proxyMode = getProperties().getProperty("proxyMode");
		if(proxyMode == null)
		{
			throw new DBException("Proxy mode is not specified");
		}
		else if(proxyMode.equals("1"))
		{
			m_proxyMode = 1;
		}
		else if(proxyMode.equals("2"))
		{
			m_proxyMode = 2;			
		}
		else if(proxyMode.equals("3"))
		{
			m_proxyMode = 3;			
		}
		else
		{
			throw new DBException("Proxy mode should be 1-2-3");			
		}
		
		try
		{
			m_proxy = getProxy(m_proxyMode, confData, confBucket);
			
			m_proxy.createTable(m_tableName, families);
			m_proxy.connect(m_tableName);
		}
		catch(Exception e)
		{
			e.printStackTrace();
			throw new DBException(e.getMessage());
		}
	}
    
	public int delete(String arg0, String arg1) 
	{
		// TODO Auto-generated method stub
		return 0;
	}

	public int insert(String tableName, String key,	HashMap<String, ByteIterator> values) 
	{
		return update(tableName, key, values);
	}
	
	public int read(String tableName, String key, Set<String> fields, HashMap<String, ByteIterator> result) 
	{
		Result r = null;

		//keys are in the form "user123123". I want to cut away "user" part.
		String realKey = key.substring(4, key.length()-1);
		long longKey = Long.parseLong(realKey);
		
		Get g = new Get(Bytes.toBytes(longKey));
		if(fields == null)
		{
			g.addFamily(m_familyName);
		}
		else
		{
			for(String field : fields)
			{
				g.addColumn(m_familyName, Bytes.toBytes(field));
			}
		}
		
		try
		{
			r = m_proxy.get(g);
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return ServerError;
		}
		
		for(KeyValue kv : r.raw())
		{
			result.put(Bytes.toString(kv.getQualifier()), new ByteArrayByteIterator(kv.getValue()));
		}
		
		return Ok;
	}
	
	public int scan(String table, String startKey, int recordCount, Set<String> fields, Vector<HashMap<String, ByteIterator>> result) 
	{
		//keys are in the form "user123123". I want to cut away "user" part.
		String realKey = startKey.substring(4, startKey.length()-1);
		long longKey = Long.parseLong(realKey);
				
		Scan s = new Scan();
		s.setStartRow(Bytes.toBytes(longKey));
		s.setStopRow(Bytes.toBytes(longKey + recordCount));
		
		if(fields == null)
		{
			s.addFamily(m_familyName);
		}
		else
		{
			for(String field : fields)
			{
				s.addColumn(m_familyName, Bytes.toBytes(field));
			}
		}
		
		ResultScanner scanner = null;
		try
		{
			scanner = m_proxy.getScanner(s);
			int numResults = 0;
			for(Result rr = scanner.next(); rr != null; scanner.next())
			{
				HashMap<String, ByteIterator> rowResult = new HashMap<String, ByteIterator>();
				for(KeyValue kv : rr.raw())
				{
					rowResult.put(Bytes.toString(kv.getQualifier()), new ByteArrayByteIterator(kv.getValue()));
				}
				
				result.add(rowResult);
				numResults++;
				
				if(numResults >= recordCount)
					break;
			}
		}
		catch (Exception e)
		{
			e.printStackTrace();
			return ServerError;
		}
		finally
		{
			scanner.close();
		}
		
		return Ok;
	}

	public int update(String tableName, String key,	HashMap<String, ByteIterator> values) 
	{
		//keys are in the form "user123123". I want to cut away "user" part.
		String realKey = key.substring(4, key.length()-1);
		long longKey = Long.parseLong(realKey);
		
		Put p = new Put(Bytes.toBytes(longKey));
		for (Map.Entry<String, ByteIterator> entry : values.entrySet())
		{
			p.add(m_familyName, Bytes.toBytes(entry.getKey()), entry.getValue().toArray());
		}
		
		try
        {
            m_proxy.put(p);			
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return ServerError;
        }
		
		return Ok;
	}
}
