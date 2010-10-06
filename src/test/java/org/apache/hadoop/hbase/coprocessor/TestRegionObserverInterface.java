/**
 * Copyright 2010 The Apache Software Foundation
 *
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.hadoop.hbase.coprocessor;

import java.io.IOException;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HRegionInfo;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.coprocessor.Coprocessor.Priority;
import org.apache.hadoop.hbase.coprocessor.CoprocessorEnvironment;
import org.apache.hadoop.hbase.regionserver.CoprocessorHost;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.util.Bytes;
import org.junit.Test;

import static org.junit.Assert.*;

public class TestRegionObserverInterface {
  static final Log LOG = LogFactory.getLog(TestRegionObserverInterface.class);
  static final String DIR = "test/build/data/TestRegionObserver/";

  static byte[] A = Bytes.toBytes("a");
  static byte[] B = Bytes.toBytes("b");
  static byte[] C = Bytes.toBytes("c");
  static byte[] ROW = Bytes.toBytes("testrow");
  static byte[] ROW1 = Bytes.toBytes("testrow1");
  static byte[] ROW2 = Bytes.toBytes("testrow2");

  public static class SimpleRegionObserver extends BaseRegionObserver {
    boolean beforeDelete = true;
    boolean scannerOpened = false;
    boolean hadPreGet = false;
    boolean hadPostGet = false;
    boolean hadPrePut = false;
    boolean hadPostPut = false;
    boolean hadPreDeleted = false;
    boolean hadPostDeleted = false;
    boolean hadPreGetClosestRowBefore = false;
    boolean hadPostGetClosestRowBefore = false;

    // Overriden RegionObserver methods
    @Override
    public List<KeyValue> preGet(CoprocessorEnvironment e, Get get,
        List<KeyValue> results) {
      // is there a way to test this hook?
      LOG.info("preGet: get=" + get);
      hadPreGet = true;
      assertNotNull(e);
      assertNotNull(e.getRegion());
      return null;
    }

    @Override
    public List<KeyValue> postGet(CoprocessorEnvironment e, Get get, List<KeyValue> results) {
      LOG.info("postGet: get=" + get);
      assertTrue(Bytes.equals(get.getRow(), ROW));
      if (beforeDelete) {
        assertNotNull(results.get(0));
        assertTrue(Bytes.equals(results.get(0).getRow(), ROW));
        boolean foundA = false;
        boolean foundB = false;
        boolean foundC = false;
        for (KeyValue kv: results) {
          if (Bytes.equals(kv.getFamily(), A)) {
            foundA = true;
          }
          if (Bytes.equals(kv.getFamily(), B)) {
            foundB = true;
          }
          if (Bytes.equals(kv.getFamily(), C)) {
            foundC = true;
          }
        }
        assertTrue(foundA);
        assertTrue(foundB);
        assertTrue(foundC);
        hadPostGet = true;
      } else {
        assertTrue(results.isEmpty());
      }
      return results;
    }

    @Override
    public Map<byte[], List<KeyValue>> prePut(CoprocessorEnvironment e,
        Map<byte[], List<KeyValue>> familyMap) {
      LOG.info("onPut put=" + familyMap);
      List<KeyValue> kvs = familyMap.get(A);
      assertNotNull(kvs);
      assertNotNull(kvs.get(0));
      assertTrue(Bytes.equals(kvs.get(0).getQualifier(), A));
      kvs = familyMap.get(B);
      assertNotNull(kvs);
      assertNotNull(kvs.get(0));
      assertTrue(Bytes.equals(kvs.get(0).getQualifier(), B));
      kvs = familyMap.get(C);
      assertNotNull(kvs);
      assertNotNull(kvs.get(0));
      assertTrue(Bytes.equals(kvs.get(0).getQualifier(), C));
      hadPrePut = true;
      return familyMap;
    }

    @Override
    public Map<byte[], List<KeyValue>> postPut(CoprocessorEnvironment e,
        Map<byte[], List<KeyValue>> familyMap) {
      LOG.info("onPut put=" + familyMap);
      List<KeyValue> kvs = familyMap.get(A);
      assertNotNull(kvs);
      assertNotNull(kvs.get(0));
      assertTrue(Bytes.equals(kvs.get(0).getQualifier(), A));
      kvs = familyMap.get(B);
      assertNotNull(kvs);
      assertNotNull(kvs.get(0));
      assertTrue(Bytes.equals(kvs.get(0).getQualifier(), B));
      kvs = familyMap.get(C);
      assertNotNull(kvs);
      assertNotNull(kvs.get(0));
      assertTrue(Bytes.equals(kvs.get(0).getQualifier(), C));
      hadPostPut = true;
      return familyMap;
    }

    @Override
    public Map<byte[], List<KeyValue>> preDelete(CoprocessorEnvironment e,
        Map<byte[], List<KeyValue>> familyMap) {
      LOG.info("preDelete: delete=" + familyMap);
      hadPreDeleted = true;
      return familyMap;
    }

    @Override
    public Map<byte[], List<KeyValue>> postDelete(CoprocessorEnvironment e,
        Map<byte[], List<KeyValue>> familyMap) {
      LOG.info("postDelete: delete=" + familyMap);
      beforeDelete = false;
      hadPostDeleted = true;
      return familyMap;
    }

    @Override
    public Result preGetClosestRowBefore(final CoprocessorEnvironment e, final byte[] row,
        final byte[] family, Result result) {
      hadPreGetClosestRowBefore = true;
      return result;
    }

    @Override
    public Result postGetClosestRowBefore(final CoprocessorEnvironment e, final byte[] row,
        final byte[] family, Result result) {
      hadPostGetClosestRowBefore = true;
      return result;
    }

    @Override
    public void preScannerOpen(CoprocessorEnvironment e, Scan scan) {
      // not tested -- need to go through the RS to get here
    }

    @Override
    public void postScannerOpen(CoprocessorEnvironment e, Scan scan, long scannerId) {
      // not tested -- need to go through the RS to get here
    }

    @Override
    public List<KeyValue> preScannerNext(final CoprocessorEnvironment e,
        final long scannerId, List<KeyValue> results) {
      // not tested -- need to go through the RS to get here
      return results;
    }

    @Override
    public List<KeyValue> postScannerNext(final CoprocessorEnvironment e,
        final long scannerId, List<KeyValue> results) {
      // not tested -- need to go through the RS to get here
      return results;
    }

    @Override
    public void preScannerClose(final CoprocessorEnvironment e,
        final long scannerId) {
      // not tested -- need to go through the RS to get here
    }

    @Override
    public void postScannerClose(final CoprocessorEnvironment e,
        final long scannerId) {
      // not tested -- need to go through the RS to get here
    }

    boolean hadPreGet() {
      return hadPreGet;
    }

    boolean hadPostGet() {
      return hadPostGet;
    }

    boolean hadPrePut() {
      return hadPrePut;
    }

    boolean hadPostPut() {
      return hadPostPut;
    }

    boolean hadDelete() {
      return !beforeDelete;
    }
  }

  HRegion initHRegion (byte [] tableName, String callingMethod,
      Configuration conf, Class<?> implClass, byte [] ... families)
      throws IOException{
    HTableDescriptor htd = new HTableDescriptor(tableName);
    for(byte [] family : families) {
      htd.addFamily(new HColumnDescriptor(family));
    }
    HRegionInfo info = new HRegionInfo(htd, null, null, false);
    Path path = new Path(DIR + callingMethod);
    // this following piece is a hack. currently a coprocessorHost
    // is secretly loaded at OpenRegionHandler. we don't really
    // start a region server here, so just manually create cphost
    // and set it to region.
    HRegion r = HRegion.createHRegion(info, path, conf);
    CoprocessorHost host = new CoprocessorHost(r, null, conf);
    r.setCoprocessorHost(host);
    host.load(implClass, Priority.USER);
    return r;
  }

  @Test
  public void testRegionObserver() throws IOException {
    byte[] TABLE = Bytes.toBytes(getClass().getName());
    byte[][] FAMILIES = new byte[][] { A, B, C } ;

    HRegion region = initHRegion(TABLE, getClass().getName(),
      HBaseConfiguration.create(), SimpleRegionObserver.class, FAMILIES);

    Put put = new Put(ROW);
    put.add(A, A, A);
    put.add(B, B, B);
    put.add(C, C, C);
    int lockid = region.obtainRowLock(ROW);
    region.put(put, lockid);
    region.releaseRowLock(lockid);

    Get get = new Get(ROW);
    get.addColumn(A, A);
    get.addColumn(B, B);
    get.addColumn(C, C);
    lockid = region.obtainRowLock(ROW);
    region.get(get, lockid);
    region.releaseRowLock(lockid);

    Delete delete = new Delete(ROW);
    delete.deleteColumn(A, A);
    delete.deleteColumn(B, B);
    delete.deleteColumn(C, C);
    lockid = region.obtainRowLock(ROW);
    region.delete(delete, lockid, true);
    region.releaseRowLock(lockid);

    // get again after delete
    lockid = region.obtainRowLock(ROW);
    region.get(get, lockid);
    region.releaseRowLock(lockid);

    Coprocessor c = region.getCoprocessorHost()
      .findCoprocessor(SimpleRegionObserver.class.getName());
    assertNotNull(c);
    assertTrue(((SimpleRegionObserver)c).hadPreGet());
    assertTrue(((SimpleRegionObserver)c).hadPostGet());
    assertTrue(((SimpleRegionObserver)c).hadPrePut());
    assertTrue(((SimpleRegionObserver)c).hadPostPut());
    assertTrue(((SimpleRegionObserver)c).hadDelete());
  }
}

