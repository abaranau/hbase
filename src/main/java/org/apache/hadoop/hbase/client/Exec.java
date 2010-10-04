/*
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
package org.apache.hadoop.hbase.client;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.io.HbaseObjectWritable;
import org.apache.hadoop.hbase.ipc.CoprocessorProtocol;
import org.apache.hadoop.hbase.ipc.Invocation;
import org.apache.hadoop.hbase.util.Bytes;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.lang.reflect.Method;

/**
 * Represents an arbitrary protocol method invocation.
 */
public class Exec extends Invocation implements Row {
  private Configuration conf = HBaseConfiguration.create();
  /** Row key used as a reference for any region lookups */
  private byte[] referenceRow;
  private Class<? extends CoprocessorProtocol> protocol;

  public Exec() {
  }

  public Exec(Configuration configuration,
      byte[] row,
      Class<? extends CoprocessorProtocol> protocol,
      Method method, Object[] parameters) {
    super(method, parameters);
    this.conf = configuration;
    this.referenceRow = row;
    this.protocol = protocol;
  }

  public Class<? extends CoprocessorProtocol> getProtocol() {
    return protocol;
  }

  public byte[] getRow() {
    return referenceRow;
  }

  public int compareTo(Row row) {
    return Bytes.compareTo(referenceRow, row.getRow());
  }

  @Override
  public void write(DataOutput out) throws IOException {
    super.write(out);
    Bytes.writeByteArray(out, referenceRow);
    out.writeUTF(protocol.getName());
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    super.readFields(in);
    referenceRow = Bytes.readByteArray(in);
    String protocolName = in.readUTF();
    try {
      protocol = (Class<CoprocessorProtocol>)conf.getClassByName(protocolName);
    }
    catch (ClassNotFoundException cnfe) {
      throw new IOException("Protocol class "+protocolName+" not found", cnfe);
    }
  }
}
