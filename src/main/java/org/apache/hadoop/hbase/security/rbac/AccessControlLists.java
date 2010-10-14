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

package org.apache.hadoop.hbase.security.rbac;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.ListMultimap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.HRegionInfo;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.catalog.CatalogTracker;
import org.apache.hadoop.hbase.client.Put;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.ResultScanner;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.filter.CompareFilter;
import org.apache.hadoop.hbase.filter.RegexStringComparator;
import org.apache.hadoop.hbase.filter.RowFilter;
import org.apache.hadoop.hbase.io.HbaseObjectWritable;
import org.apache.hadoop.hbase.ipc.HRegionInterface;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.InternalScanner;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.hbase.util.Pair;
import org.apache.hadoop.hbase.util.Writables;
import org.apache.hadoop.io.Text;

import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

public class AccessControlLists {
  /** delimiter to separate user and column family in .META. acl: column keys */
  public static final char ACL_KEY_DELIMITER = ',';
  /** prefix character to denote group names */
  public static final String GROUP_PREFIX = "@";
  /** column qualifier for table owner */
  public static final byte[] OWNER_QUALIFIER = Bytes.toBytes("owner");

  private static Log LOG = LogFactory.getLog(AccessControlLists.class);

  public static void addTablePermission(CatalogTracker tracker,
      HRegionInfo firstRegion, String username, TablePermission perm)
    throws IOException {

    Put p = new Put(firstRegion.getRegionName());
    byte[] key = null;
    if (perm.getFamily() != null && perm.getFamily().length > 0) {
      key = Bytes.toBytes(username + ACL_KEY_DELIMITER +
          Bytes.toString(perm.getFamily()));
    } else {
      key = Bytes.toBytes(username);
    }

    TablePermission.Action[] actions = perm.getActions();
    if ((actions == null) || (actions.length == 0)) {
      LOG.warn("No actions associated with user '"+username+"'");
      return;
    }

    byte[] value = new byte[actions.length];
    for (int i=0; i<actions.length; i++) {
      value[i] = actions[i].code();
    }
    p.add(HConstants.ACL_FAMILY, key, value);
    if (LOG.isDebugEnabled()) {
      LOG.debug("Writing permission for table "+
          Bytes.toString(firstRegion.getTableDesc().getName())+" "+
          Bytes.toString(key)+": "+Bytes.toStringBinary(value)
      );
    }

    tracker.waitForMetaServerConnectionDefault().put(
        CatalogTracker.META_REGION, p);
  }

  public static Map<byte[],ListMultimap<String,TablePermission>> loadAll(
      HRegion metaRegion)
    throws IOException {

    if (!metaRegion.getRegionInfo().isMetaRegion()) {
      throw new IOException("Can only load permissions from .META.");
    }

    Map<byte[],ListMultimap<String,TablePermission>> allPerms =
        new TreeMap<byte[],ListMultimap<String,TablePermission>>(Bytes.BYTES_COMPARATOR);
    
    // do a full scan of .META., filtering on only first table region rows

    Scan scan = new Scan();
    scan.addFamily(HConstants.ACL_FAMILY);
    scan.addColumn(HConstants.CATALOG_FAMILY, HConstants.REGIONINFO_QUALIFIER);
    scan.setFilter(new RowFilter(CompareFilter.CompareOp.EQUAL,
        new RegexStringComparator("^[\\w\\-\\.]+,,")));

    InternalScanner iScanner = null;
    try {
      iScanner = metaRegion.getScanner(scan);

      while (true) {
        List<KeyValue> row = new ArrayList<KeyValue>();

        boolean hasNext = iScanner.next(row);
        ListMultimap<String,TablePermission> perms = ArrayListMultimap.create();
        byte[] table = null;
        for (KeyValue kv : row) {
          if (table == null) {
            String rowkey = Bytes.toStringBinary(kv.getRow());
            table = Bytes.toBytes( rowkey.substring(0, rowkey.indexOf(',')) );
          }
          Pair<String,TablePermission> permissionsOfUserOnTable =
              parsePermissionRecord(table,kv);
          if (permissionsOfUserOnTable != null) {
            String username = permissionsOfUserOnTable.getFirst();
            TablePermission permissions = permissionsOfUserOnTable.getSecond();
            perms.put(username, permissions);
          }
        }
        allPerms.put(table, perms);
        if (!hasNext) {
          break;
        }
      }
    } finally {
      if (iScanner != null) {
        iScanner.close();
      }
    }

    return allPerms;
  }

  /**
   * Load all permissions from the region server holding .META., primarily
   * intended for testing purposes.
   *
   * @param tracker
   * @return
   * @throws IOException
   */
  public static Map<byte[],ListMultimap<String,TablePermission>> loadAll(
      CatalogTracker tracker) throws IOException {
    Map<byte[],ListMultimap<String,TablePermission>> allPerms =
        new TreeMap<byte[],ListMultimap<String,TablePermission>>(Bytes.BYTES_COMPARATOR);

    // do a full scan of .META., filtering on only first table region rows

    Scan scan = new Scan();
    scan.addFamily(HConstants.ACL_FAMILY);
    scan.addColumn(HConstants.CATALOG_FAMILY, HConstants.REGIONINFO_QUALIFIER);
    scan.setFilter(new RowFilter(CompareFilter.CompareOp.EQUAL,
        new RegexStringComparator("^[\\w\\-\\.]+,,")));
    HRegionInterface connection = tracker.waitForMetaServerConnectionDefault();
    long scannerId =
        connection.openScanner(
            HRegionInfo.FIRST_META_REGIONINFO.getRegionName(), scan);

    try {
      Result row = null;
      while((row = connection.next(scannerId)) != null) {
        HRegionInfo regionInfo = Writables.getHRegionInfo(
            row.getValue(HConstants.CATALOG_FAMILY, HConstants.REGIONINFO_QUALIFIER));
        ListMultimap<String,TablePermission> resultPerms =
            parsePermissions(regionInfo.getTableDesc().getName(), row);
        allPerms.put(regionInfo.getTableDesc().getName(), resultPerms);
      }
    } finally {
      connection.close(scannerId);
    }

    return allPerms;
  }

  /**
   * Reads user permission assignments stored in the <code>acl:</code> column
   * family of the first table row in <code>.META.</code>.
   *
   * <p>
   * KeyValues for permissions assignments are stored in one of the formats:
   * <pre>
   * Key            Desc
   * --------       --------
   * user           table level permissions for a user [R=read, W=write]
   * @group         table level permissions for a group
   * user,family    column family level permissions for a user
   * @group,family  column family level permissions for a group
   * </pre>
   * All values are encoded as byte arrays containing the codes from the
   * {@link org.apache.hadoop.hbase.security.rbac.TablePermission.Action} enum.
   * </p>
   */
  public static ListMultimap<String,TablePermission> getTablePermissions(
      CatalogTracker tracker, byte[] tableName)
  throws IOException {
    // TODO: -ROOT- and .META. not handled with .META. acl: storage, what to do here?
    if (Bytes.equals(tableName, HConstants.ROOT_TABLE_NAME) ||
        Bytes.equals(tableName, HConstants.META_TABLE_NAME)) {
      return ArrayListMultimap.create(0,0);
    }

    // for normal user tables, we just read from the first .META. row for the table
    HRegionInterface metaServer = tracker.waitForMetaServerConnectionDefault();

    byte[] firstRow = Bytes.toBytes(Bytes.toString(tableName)+",,");
    Scan scan = new Scan(firstRow);
    scan.setCaching(1);
    scan.addFamily(HConstants.ACL_FAMILY);
    long scannerId =
        metaServer.openScanner(
            HRegionInfo.FIRST_META_REGIONINFO.getRegionName(), scan);

    ListMultimap<String,TablePermission> perms = null;
    try {
      Result acls = metaServer.next(scannerId);
      perms = parsePermissions(tableName, acls);
    } finally {
      metaServer.close(scannerId);
    }

    return perms;
  }

  private static ListMultimap<String,TablePermission> parsePermissions(
      byte[] table, Result result) {
    ListMultimap<String,TablePermission> perms = ArrayListMultimap.create();
    if (result != null && result.size() > 0) {
      byte[] lastKey = null;
      for (KeyValue kv : result.sorted()) {

        Pair<String,TablePermission> permissionsOfUserOnTable = parsePermissionRecord(table,kv);

        if (permissionsOfUserOnTable != null) {
          String username = permissionsOfUserOnTable.getFirst();
          TablePermission permissions = permissionsOfUserOnTable.getSecond();
          perms.put(username, permissions);
        }
      }
    }
    return perms;
  }

  private static Pair<String,TablePermission> parsePermissionRecord(
                                                                    byte[] table, KeyValue kv) {
    // return X given a set of permissions encoded in the permissionRecord kv.
    byte[] family = kv.getFamily();

    if (!Bytes.equals(family, HConstants.ACL_FAMILY)) {
      return null;
    }

    byte[] key = kv.getQualifier();
    if (Bytes.equals(key, OWNER_QUALIFIER)) {
      return null;
    }

    byte[] value = kv.getValue();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Read acl: kv ["+
                Bytes.toStringBinary(key)+": "+
                Bytes.toStringBinary(value)+"]");
    }

    // check for a column family appended to the key
    String username = Bytes.toString(key);
    int idx = username.lastIndexOf(ACL_KEY_DELIMITER);
    byte[] permFamily = null;
    if (idx > 0 && idx < username.length()-1) {
      permFamily = Bytes.toBytes(username.substring(idx+1));
      username = username.substring(0, idx);
    }

    return new Pair<String,TablePermission>(username,new TablePermission(table,permFamily,value));
  }

  /**
   * Writes a set of permissions as {@link org.apache.hadoop.io.Writable} instances
   * to the given output stream.
   * @param out
   * @param perms
   * @param conf
   * @throws IOException
   */
  public static void writePermissions(DataOutput out,
      ListMultimap<String,TablePermission> perms, Configuration conf)
  throws IOException {
    Set<String> keys = perms.keySet();
    out.writeInt(keys.size());
    for (String key : keys) {
      Text.writeString(out, key);
      HbaseObjectWritable.writeObject(out, perms.get(key), List.class, conf);
    }
  }

  /**
   * Writes a set of permissions as {@link org.apache.hadoop.io.Writable} instances
   * and returns the resulting byte array.
   */
  public static byte[] writePermissionsAsBytes(
      ListMultimap<String,TablePermission> perms, Configuration conf) {
    try {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      writePermissions(new DataOutputStream(bos), perms, conf);
      return bos.toByteArray();
    } catch (IOException ioe) {
      // shouldn't happen here
      LOG.error("Error serializing permissions", ioe);
    }
    return null;
  }

  /**
   * Reads a set of permissions as {@link org.apache.hadoop.io.Writable} instances
   * from the input stream.
   * 
   * @param in
   * @param conf
   * @return
   * @throws IOException
   */
  public static ListMultimap<String,TablePermission> readPermissions(
      DataInput in, Configuration conf) throws IOException {
    ListMultimap<String,TablePermission> perms = ArrayListMultimap.create();
    int length = in.readInt();
    for (int i=0; i<length; i++) {
      String user = Text.readString(in);
      List<TablePermission> userPerms =
          (List)HbaseObjectWritable.readObject(in, conf);
      perms.putAll(user, userPerms);
    }

    return perms;
  }
}
