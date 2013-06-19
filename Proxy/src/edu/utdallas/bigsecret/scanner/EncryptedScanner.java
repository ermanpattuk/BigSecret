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

package edu.utdallas.bigsecret.scanner;

import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;

import edu.utdallas.bigsecret.proxy.ProxyBase;
import edu.utdallas.bigsecret.util.ByteArray;
import edu.utdallas.bigsecret.util.ScannerQueue;


/**
 * This class extends ResultScanner.<br>
 * Initially, it collects rows that satisfy Scan's properties. Also, it stores <br>
 * which encrypted rows are stored for each plain text row.<br>
 * Then, when the client queries the next row, this class calls the ProxyBase's getForScan<br>
 * function for the current row-key in turn.
 */
public class EncryptedScanner implements ResultScanner
{
	/**
	 * Proxy instance that calls creates this EncryptedScanner instance. This information is needed to get Crypter of that Proxy.
	 */
	protected ProxyBase m_proxy;
	
	/**
	 * Plain text Scan instance.
	 */
	protected Scan m_originalScan;
	
	/**
	 * Binary heap that is used to get least row.
	 */
	protected ScannerQueue m_pq;
	
	
	/**
	 * Constructor for this class. 
	 * @param proxy ProxyBase instance that calls this function.
	 * @param scan The original Scan instance that was first issued.
	 * @param transformedResult Scanner that looks at transformed Scan result.
	 * @throws Exception
	 */
	public EncryptedScanner(ProxyBase proxy, Scan scan, ResultScanner transformedResult) throws Exception 
	{
		//check inputs
		if(proxy == null)
			throw new Exception("Proxy is null");
		else if(scan == null)
			throw new Exception("Plain Scan is null");
		else if(transformedResult == null)
			throw new Exception("Scanner is null");
		
		//set crypter object
		m_proxy = proxy;
		
		//set scan object
		m_originalScan = scan;	
		
		//init queue
		m_pq = new ScannerQueue();

		//get start and end rows
		byte[] startRow = m_originalScan.getStartRow();
		byte[] endRow = m_originalScan.getStopRow();
		
		//create start and end KV values
		KeyValue startKV;
		KeyValue endKV;
		if(startRow == HConstants.EMPTY_START_ROW)
			startKV = new KeyValue();
		else
			startKV = new KeyValue(startRow, 1L);
		
		if(endRow == HConstants.EMPTY_END_ROW)
			endKV = new KeyValue();
		else
			endKV = new KeyValue(endRow, 1L);
		
		//create comparator instance
		KeyValue.KVComparator cmp = new KeyValue.KVComparator();
		
		//let's get row data from transformed scanner
		for(Result rr = transformedResult.next(); rr!= null; rr=transformedResult.next())
		{
			List<KeyValue> keylist = rr.list();
			
			for(int a = 0; a<keylist.size(); a++)
			{
				KeyValue tempItem = keylist.get(a);
				
				byte[] encQua = tempItem.getQualifier();
				
				byte[] plaRow = proxy.getCrypter().unwrapRow(tempItem);
				
				//check if unwrapped row key is in the boundaries
				if(startRow == HConstants.EMPTY_START_ROW)
				{
					if(endRow == HConstants.EMPTY_END_ROW)
					{
						//there is no boundary
						m_pq.put(plaRow, encQua);
					}
					else
					{
						//there is boundary from end row
						if(cmp.compareRows(endKV, plaRow) == 1)
						{
							m_pq.put(plaRow, encQua);
						}
					}
				}
				else
				{
					if(endRow == HConstants.EMPTY_END_ROW)
					{
						//there is boundary from start row
						if(cmp.compareRows(startKV, plaRow) != 1)
						{
							m_pq.put(plaRow, encQua);		
						}
					}
					else
					{
						//there is boundary from start and end
						if(cmp.compareRows(endKV, plaRow) == 1 && cmp.compareRows(startKV, plaRow) != 1)
						{
							m_pq.put(plaRow, encQua);
						}
					}
				}	
			}
		}

		//close transformed result scanner
		transformedResult.close();
	}
	
	
	/**
	 * This function is not implemented. It will return null always.
	 * @return Always returns null
	 */
	@Override
	public Iterator<Result> iterator() 
	{
		//this function is not implemented
		return null;
	}

	
	/**
	 * This function does not do anything.
	 */
	public void close() 
	{
		//this function is not implemented
	}
	
	
	/**
	 * This function returns next Result value for this scanner.<br>
	 * It catches the minimum row key from cache. Checks if it's false positive or not. If it's not, return the result for this row key. Otherwise 
	 * checks the next row key.
	 * @return Result if next item exists, null otherwise
	 */
	public Result next() throws IOException
	{
		Result res = null;
		
		while((res == null || res.isEmpty()) && m_pq.size() > 0)
		{
			Set<ByteArray> encQuaSet = m_pq.get();
			
			try 
			{
				res = m_proxy.getForScan(m_originalScan, encQuaSet);
			}
			catch (Exception e) 
			{
				res = null;
			}
		}
				
		return res;
	}

	
	/**
	 * This function is not implemented. Always returns null.
	 * @return Always null
	 */
	public Result[] next(int arg0) throws IOException 
	{
		return null;
	}
	
}