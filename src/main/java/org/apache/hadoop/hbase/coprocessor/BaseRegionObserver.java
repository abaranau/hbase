/*
 * Copyright 2010 The Apache Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
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

import java.util.List;
import java.util.Map;

import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.client.Delete;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Increment;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.regionserver.HRegion;
import java.io.IOException;

/**
 * An abstract class that implements Coprocessor and RegionObserver.
 * By extending it, you can create you own region observer without
 * overriding all abstract methods of Coprocessor and RegionObserver.
 */
public abstract class BaseRegionObserver implements Coprocessor,
    RegionObserver {

  @Override
  public void preOpen(CoprocessorEnvironment e) { }

  @Override
  public void postOpen(CoprocessorEnvironment e) { }

  @Override
  public void preClose(CoprocessorEnvironment e, boolean abortRequested)
    { }

  @Override
  public void postClose(CoprocessorEnvironment e, boolean abortRequested)
    { }

  @Override
  public void preFlush(CoprocessorEnvironment e) { }

  @Override
  public void postFlush(CoprocessorEnvironment e) { }

  @Override
  public void preSplit(CoprocessorEnvironment e) { }

  @Override
  public void postSplit(CoprocessorEnvironment e, HRegion l, HRegion r) { }

  @Override
  public void preCompact(CoprocessorEnvironment e, boolean willSplit) { }

  @Override
  public void postCompact(CoprocessorEnvironment e, boolean willSplit) { }

  @Override
  public Result preGetClosestRowBefore(CoprocessorEnvironment e, byte[] row,
      byte[] family, Result result) throws IOException {
    return result;
  }

  @Override
  public Result postGetClosestRowBefore(CoprocessorEnvironment e,
      byte[] row, byte[] family, Result result)
      throws IOException {
    return result;
  }

  @Override
  public List<KeyValue> preGet(CoprocessorEnvironment e, Get get,
      List<KeyValue> results)
      throws IOException {
    return results;
  }

  @Override
  public List<KeyValue> postGet(CoprocessorEnvironment e, Get get,
      List<KeyValue> results) throws IOException {
    return results;
  }

  @Override
  public void preExists(CoprocessorEnvironment e, Get get)
      throws IOException { }

  @Override
  public boolean postExists(CoprocessorEnvironment e, Get get, boolean exists)
      throws IOException {
    return exists;
  }

  @Override
  public Map<byte[], List<KeyValue>> prePut(CoprocessorEnvironment e,
      Map<byte[], List<KeyValue>> familyMap) throws IOException {
    return familyMap;
  }

  @Override
  public Map<byte[], List<KeyValue>> postPut(CoprocessorEnvironment e,
      Map<byte[], List<KeyValue>> familyMap) throws IOException {
    return familyMap;
  }

  @Override
  public Map<byte[], List<KeyValue>> preDelete(CoprocessorEnvironment e,
      Map<byte[], List<KeyValue>> familyMap) throws IOException {
    return familyMap;
  }

  @Override
  public Map<byte[], List<KeyValue>> postDelete(CoprocessorEnvironment e,
      Map<byte[], List<KeyValue>> familyMap) throws IOException {
    return familyMap;
  }

  @Override
  public void preCheckAndPut(final CoprocessorEnvironment e,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final byte [] value, final Put put)
    throws IOException { }

  @Override
  public boolean postCheckAndPut(final CoprocessorEnvironment e,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final byte [] value, final Put put, final boolean result)
    throws IOException {
    return result;
  }

  @Override
  public void preCheckAndDelete(final CoprocessorEnvironment e,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final byte [] value, final Delete delete)
    throws IOException { }

  @Override
  public boolean postCheckAndDelete(final CoprocessorEnvironment e,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final byte [] value, final Delete delete, final boolean result)
    throws IOException {
    return result;
  }

  @Override
  public long preIncrementColumnValue(final CoprocessorEnvironment e,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final long amount, final boolean writeToWAL) throws IOException {
    return amount;
  }

  @Override
  public long postIncrementColumnValue(final CoprocessorEnvironment e,
      final byte [] row, final byte [] family, final byte [] qualifier,
      final long amount, final boolean writeToWAL, long result)
  throws IOException {
    return result;
  }

  @Override
  public Increment preIncrement(CoprocessorEnvironment e, Increment increment) 
  throws IOException {
    return increment;
  }

  @Override
  public Result postIncrement(CoprocessorEnvironment e, Increment increment,
      Result result) throws IOException {
    return result;
  }

  @Override
  public void preScannerOpen(CoprocessorEnvironment e, Scan scan)
    throws IOException { }

  @Override
  public void postScannerOpen(CoprocessorEnvironment e, Scan scan,
    long scannerId) throws IOException { }

  @Override
  public List<KeyValue> preScannerNext(CoprocessorEnvironment e,
      long scannerId, List<KeyValue> results) throws IOException {
    return results;
  }

  @Override
  public List<KeyValue> postScannerNext(CoprocessorEnvironment e,
      long scannerId, List<KeyValue> results)
      throws IOException {
    return results;
  }

  @Override
  public void preScannerClose(CoprocessorEnvironment e, long scannerId)
    throws IOException { }

  @Override
  public void postScannerClose(CoprocessorEnvironment e, long scannerId)
    throws IOException { }
}
