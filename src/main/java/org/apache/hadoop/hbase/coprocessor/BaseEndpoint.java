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

import java.io.IOException;

import org.apache.hadoop.hbase.ipc.CoprocessorProtocol;
import org.apache.hadoop.hbase.ipc.HBaseRPCProtocolVersion;
import org.apache.hadoop.hbase.regionserver.HRegion;

/**
 * CommandTarget base class.
 * Extend this class and implement related CoprocessorProtocol
 * to implement actually class running at region server.
 */
public abstract class BaseEndpoint implements Coprocessor,
    CoprocessorProtocol {
  private CoprocessorEnvironment env;

  /**
   * @param e Coprocessor environment.
   */
  private void setEnvironment(CoprocessorEnvironment e) {
    env = e;
  }

  /**
   * @return env Coprocessor environment.
   */
  public CoprocessorEnvironment getEnvironment() {
    return env;
  }

  @Override
  public long getProtocolVersion(String arg0, long arg1) throws IOException {
    return HBaseRPCProtocolVersion.versionID;
  }

  @Override
  public void preOpen(CoprocessorEnvironment e) { }

  @Override
  public void postOpen(CoprocessorEnvironment e) {
    setEnvironment(e);
  }

  @Override
  public void preClose(CoprocessorEnvironment e, boolean abortRequested) { }

  @Override
  public void postClose(CoprocessorEnvironment e, boolean abortRequested) { }

  @Override
  public void preFlush(CoprocessorEnvironment e) { }

  @Override
  public void postFlush(CoprocessorEnvironment e) { }

  @Override
  public void preCompact(CoprocessorEnvironment e, boolean willSplit) { }

  @Override
  public void postCompact(CoprocessorEnvironment e, boolean willSplit) { }

  @Override
  public void preSplit(CoprocessorEnvironment e) { }

  @Override
  public void postSplit(CoprocessorEnvironment e, HRegion l, HRegion r) { }
}
