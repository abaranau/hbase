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

package org.apache.hadoop.hbase.coprocessor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.fs.FSDataOutputStream;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.hbase.HBaseClusterTestCase;
import org.apache.hadoop.hbase.HColumnDescriptor;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.MiniHBaseCluster;
import org.apache.hadoop.hbase.client.HBaseAdmin;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.util.Base64;
import org.apache.hadoop.hdfs.MiniDFSCluster;
import org.apache.hadoop.hbase.regionserver.CoprocessorHost;

public class TestClassloading extends HBaseClusterTestCase {
  static final Log LOG = LogFactory.getLog(TestClassloading.class);

  // This is a jar that contains a basic manifest and a single class
  // org/apache/hadoop/hbase/coprocessor/TestClassloading_Main which
  // implements the Coprocessor interface
  //
  // The ideal way is to generate the jar file at build process and
  // load it as a java resource.
  //
  // Source code:
  //
  // package org.apache.hadoop.hbase.coprocessor;
  // public class TestClassloading_Main extends BaseRegionObserver {
  // }
  // TODO: generate the jar file at build process or compile it
  // by JavaCompiler.

  final static String encJar =
    "UEsDBBQACAAIAElOKT0AAAAAAAAAAAAAAAAJAAQATUVUQS1JTkYv/soAAAMAUEsHCAAAAAACAAAA"+
    "AAAAAFBLAwQUAAgACABJTik9AAAAAAAAAAAAAAAAFAAAAE1FVEEtSU5GL01BTklGRVNULk1G803M"+
    "y0xLLS7RDUstKs7Mz7NSMNQz4OVyLkpNLElN0XWqBAmY6RnEG1ooaASX5in4ZiYX5RdXFpek5hYr"+
    "eOYl62nycvFyAQBQSwcIBLuBuEcAAABHAAAAUEsDBBQACAAIADZOKT0AAAAAAAAAAAAAAAA/AAAA"+
    "b3JnL2FwYWNoZS9oYWRvb3AvaGJhc2UvY29wcm9jZXNzb3IvVGVzdENsYXNzbG9hZGluZ19NYWlu"+
    "LmNsYXNznVA9S8RAEH17l0s0Rk8s7ezUwgULQU4sPLCKCnpcK5NkSFZiJuzm7n9ZCRb+AH+UuImW"+
    "FuIMPOY93nwwH59v7wBOsRtjjO0IOxGmCuGFaUx3qTA+PFoqBHMpWGGamoZvV88Z2wVltVf2Usmp"+
    "XpI1Pf8Rg64yTmGWii01tZRXrCsqRFpdZeRY59Jaydk5sXrBrpvX5FwtVJimfLwh08wU4gdZ2Zyv"+
    "TT9x/1fXyROtKUGAicL5v3cpnP2l98oL91waae4yx3bNFgcY+Z/1oXz6MzyGnumBA5PjV6gXX4wQ"+
    "eQwHMcCGx+TbgE3EQ/vW4Eq+AFBLBwjVz2i08QAAAI4BAABQSwECFAAUAAgACABJTik9AAAAAAIA"+
    "AAAAAAAACQAEAAAAAAAAAAAAAAAAAAAATUVUQS1JTkYv/soAAFBLAQIUABQACAAIAElOKT0Eu4G4"+
    "RwAAAEcAAAAUAAAAAAAAAAAAAAAAAD0AAABNRVRBLUlORi9NQU5JRkVTVC5NRlBLAQIUABQACAAI"+
    "ADZOKT3Vz2i08QAAAI4BAAA/AAAAAAAAAAAAAAAAAMYAAABvcmcvYXBhY2hlL2hhZG9vcC9oYmFz"+
    "ZS9jb3Byb2Nlc3Nvci9UZXN0Q2xhc3Nsb2FkaW5nX01haW4uY2xhc3NQSwUGAAAAAAMAAwDqAAAA"+
    "JAIAAAAA";

  final static String className = "TestClassloading_Main";
  final static String classFullName =
    "org.apache.hadoop.hbase.coprocessor.TestClassloading_Main";

  public void testClassLoadingFromHDFS() throws Exception {
    MiniDFSCluster dfs = this.dfsCluster;
    FileSystem fs = dfs.getFileSystem();

    // write the jar into dfs
    Path path = new Path(fs.getUri() + Path.SEPARATOR +
      "TestClassloading.jar");
    FSDataOutputStream os = fs.create(path, true);
    os.write(Base64.decode(encJar));
    os.close();

    // create a table that references the jar
    HTableDescriptor htd = new HTableDescriptor(getClass().getName());
    htd.addFamily(new HColumnDescriptor("test"));
    htd.setValue("Coprocessor$1",
      path.toString() +
      ":" + classFullName +
      ":" + Coprocessor.Priority.USER);
    HBaseAdmin admin = new HBaseAdmin(this.conf);
    admin.createTable(htd);

    // verify that the coprocessor was loaded
    boolean found = false;
    MiniHBaseCluster hbase = this.cluster;
    for (HRegion region: hbase.getRegionServer(0).getOnlineRegionsLocalContext()) {
      if (region.getRegionNameAsString().startsWith(getClass().getName())) {
        CoprocessorHost host = region.getCoprocessorHost();
        Coprocessor c = host.findCoprocessor(className);
        found = (c != null);
      }
    }
    assertTrue(found);
  }
}
