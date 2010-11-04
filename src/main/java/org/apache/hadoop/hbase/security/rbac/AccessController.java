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

package org.apache.hadoop.hbase.security.rbac;

import com.google.common.collect.ListMultimap;
import com.google.common.collect.Lists;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.HConstants;
import org.apache.hadoop.hbase.HTableDescriptor;
import org.apache.hadoop.hbase.KeyValue;
import org.apache.hadoop.hbase.HRegionInfo;
import org.apache.hadoop.hbase.catalog.CatalogTracker;
import org.apache.hadoop.hbase.client.Get;
import org.apache.hadoop.hbase.client.Result;
import org.apache.hadoop.hbase.client.Scan;
import org.apache.hadoop.hbase.coprocessor.BaseRegionObserver;
import org.apache.hadoop.hbase.coprocessor.CoprocessorEnvironment;
import org.apache.hadoop.hbase.coprocessor.CoprocessorException;
import org.apache.hadoop.hbase.ipc.HBaseRPC;
import org.apache.hadoop.hbase.ipc.RequestContext;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.security.AccessDeniedException;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.security.UserGroupInformation;
import java.io.IOException;
import java.util.*;

public class AccessController extends BaseRegionObserver {
  public static final Log LOG = LogFactory.getLog(AccessController.class);

  TableAuthManager authManager = null;
  boolean isMetaRegion = false;

  void openMetaRegion(CoprocessorEnvironment e) throws IOException {
    final HRegion region = e.getRegion();

    Map<byte[],ListMultimap<String,TablePermission>> tables =
        AccessControlLists.loadAll(region);
    // For each table, write out the table's permissions to the respective
    // znode for that table.
    for (Map.Entry<byte[],ListMultimap<String,TablePermission>> t:
      tables.entrySet()) {
      byte[] table = t.getKey();
      String tableName = Bytes.toString(table);
      ListMultimap<String,TablePermission> perms = t.getValue();
      byte[] serialized = AccessControlLists.writePermissionsAsBytes(perms,
          e.getRegion().getConf());
      this.authManager.getZKPermissionWatcher().writeToZookeeper(tableName,
        serialized);
    }
  }

  void updateACL(CoprocessorEnvironment e,
      final Map<byte[], List<KeyValue>> familyMap) {
    Set<String> tableSet = new HashSet<String>();
    for (Map.Entry<byte[], List<KeyValue>> f : familyMap.entrySet()) {
      List<KeyValue> kvs = f.getValue();
      for (KeyValue kv: kvs) {
        if (Bytes.compareTo(kv.getBuffer(), kv.getFamilyOffset(),
            kv.getFamilyLength(), HConstants.ACL_FAMILY, 0,
            HConstants.ACL_FAMILY.length) == 0) {
          String row = Bytes.toString(kv.getRow());
          String tableName = row.substring(0, row.indexOf(","));
          tableSet.add(tableName);
        }
      }
    }
    CatalogTracker ct = e.getRegionServerServices().getCatalogTracker();
    for (String tableName: tableSet) {
      try {
        ListMultimap<String,TablePermission> perms =
          AccessControlLists.getTablePermissions(ct, Bytes.toBytes(tableName));
        byte[] serialized = AccessControlLists.writePermissionsAsBytes(
            perms, e.getRegion().getConf());
        this.authManager.getZKPermissionWatcher().writeToZookeeper(tableName,
          serialized);
      } catch (IOException ex) {
        LOG.error("Failed updating permissions mirror for '" + tableName +
          "'", ex);
      }
    }
  }

  void updateACL(CoprocessorEnvironment e, final KeyValue kv) {
    if (Bytes.compareTo(kv.getBuffer(), kv.getFamilyOffset(),
        kv.getFamilyLength(), HConstants.ACL_FAMILY, 0,
        HConstants.ACL_FAMILY.length) == 0) {
      String row = Bytes.toString(kv.getRow());
      String tableName = row.substring(0, row.indexOf(","));
      CatalogTracker ct = e.getRegionServerServices().getCatalogTracker();
      try {
        ListMultimap<String,TablePermission> perms =
          AccessControlLists.getTablePermissions(ct, Bytes.toBytes(tableName));
        byte[] serialized = AccessControlLists.writePermissionsAsBytes(perms,
            e.getRegion().getConf());
        this.authManager.getZKPermissionWatcher().writeToZookeeper(tableName,
          serialized); 
      } catch (IOException ex) {
        LOG.error("Failed updating permissions mirror for '" + tableName +
          "'", ex);
      }
    }
  }

  boolean permissionGranted(TablePermission.Action permRequest,
      CoprocessorEnvironment e, Collection<byte[]> families) {
    HRegionInfo hri = e.getRegion().getRegionInfo();
    HTableDescriptor htd = hri.getTableDesc();

    // 1. All users need read access to .META. and -ROOT- tables; also, this is a very
    // common call to permissionGranted(), so deal with it quickly.
    if ((isMetaRegion || (htd.isRootRegion())) &&
        (permRequest == TablePermission.Action.READ)) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("All users are allowed to " + permRequest.toString() +
          " the table '" + htd.getNameAsString() + "'");
      }
      return true;
    }

    // 2. Get owner of this table: owners can do anything, (including the 
    // specific permRequest requested).
    // Note that .META. and -ROOT- set on creation to be owned by the system
    // user: (see MasterFileSystem.java:bootstrap()), so that only system user
    // may write to them.  Of course, other users may be later granted write
    // access to these tables if desired.
    String owner = htd.getOwnerString();
    if (owner == null) {
      LOG.debug("Owner of '" + htd.getNameAsString() + " is (incorrectly) null.");
    }

    UserGroupInformation user = RequestContext.getRequestUser();
    if (user == null) {
      LOG.info("No user associated with request.  Permission denied!");
      return false;
    }

    if (user.getShortUserName().equals(owner)) {
      // owner of table can do anything to the table.
      if (LOG.isDebugEnabled()) {
        LOG.debug("User '" + user.getShortUserName() + "' is owner: allowed to " +
          permRequest.toString() + " the table '" + htd.getNameAsString() +
          "'");
      }
      return true;
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("User '" + user.getShortUserName() +
        "' is not owner of the table '" + htd.getNameAsString() +
        "' (owner is : '" + owner + "')");
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("Owner-based authorization did not succeed, " +
        "continuing with user-based authorization check");
    }
    boolean result = false;

    // 3. get permissions for this user for table with desc tableDesc.
    if (families != null && families.size() > 0) {
      // all families must pass
      result = true;
      for (byte[] family : families) {
        result = result &&
            authManager.authorize(user, htd.getName(), family, permRequest);
        if (!result) {
          break;  //failed
        }
      }
    } else {
      // just check for the table-level
      result = authManager.authorize(user, htd.getName(), null, permRequest);
    }

    if (LOG.isDebugEnabled()) {
      LOG.debug("User '" + user.getShortUserName() + "' is " +
        (result ? "" : "not ") + "allowed to " +
        permRequest.toString() + " the table '" + htd.getNameAsString() +
        "'");
    }

    return result;
  }

  public void requirePermission(TablePermission.Action perm,
        CoprocessorEnvironment env, Collection<byte[]> families)
      throws IOException {
    if (!permissionGranted(perm, env,families)) {
      throw new AccessDeniedException("Insufficient permissions (table=" +
        env.getRegion().getTableDesc().getNameAsString()+", action=" +
        perm.toString());
    }
  }

  @Override
  public void postOpen(CoprocessorEnvironment e) {
    final HRegion region = e.getRegion();
    HRegionInfo regionInfo = null;
    HTableDescriptor tableDesc = null;
    if (region != null) {
      regionInfo = region.getRegionInfo();
      if (regionInfo != null) {
        tableDesc = regionInfo.getTableDesc();
      }
    }

    this.authManager = TableAuthManager.get(
        e.getRegionServerServices().getZooKeeperWatcher(),
        e.getRegion().getConf());

    if (regionInfo.isRootRegion()) {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Opening -ROOT-, no op");
      }
      return;
    }

    if (tableDesc.isMetaRegion()) {
      isMetaRegion = true;
      try {
        openMetaRegion(e);
      } catch (IOException ex) {
        LOG.error("Failed to initialize permissions mirror", ex);
      }
    }
  }

  private Collection<byte[]> getFamilies(List<KeyValue> kvs) {
    TreeSet<byte[]> distinct = new TreeSet<byte[]>(Bytes.BYTES_COMPARATOR);
    for (KeyValue kv : kvs) {
      distinct.add(kv.getFamily());
    }
    return distinct;
  }

  @Override
  public void preGetClosestRowBefore(CoprocessorEnvironment e, byte[] row,
      byte[] family) throws IOException {
    requirePermission(TablePermission.Action.READ, e,
        (family != null ? Lists.newArrayList(family) : null));
  }

  @Override
  public Get preGet(CoprocessorEnvironment e, Get get) throws IOException {
    requirePermission(TablePermission.Action.READ, e, get.familySet());
    return get;
  }

  @Override
  public Get preExists(CoprocessorEnvironment e, Get get)
      throws IOException {
    requirePermission(TablePermission.Action.READ, e, get.familySet());
    return get;
  }

  @Override
  public Map<byte[], List<KeyValue>> prePut(CoprocessorEnvironment e,
      Map<byte[], List<KeyValue>> familyMap) throws IOException {
    requirePermission(TablePermission.Action.WRITE, e, familyMap.keySet());
    return familyMap;
  }

  @Override
  public void postPut(final CoprocessorEnvironment e,
      final Map<byte[], List<KeyValue>> familyMap) {
    if (isMetaRegion) {
      updateACL(e, familyMap);
    }
  }

  @Override
  public Map<byte[], List<KeyValue>> preDelete(CoprocessorEnvironment e,
      Map<byte[], List<KeyValue>> familyMap) throws IOException {
    requirePermission(TablePermission.Action.WRITE, e, familyMap.keySet());
    return familyMap;
  }

  @Override
  public void postDelete(CoprocessorEnvironment e,
      Map<byte[], List<KeyValue>> familyMap) throws CoprocessorException {
    if (isMetaRegion) {
      updateACL(e, familyMap);
    }
  }

  @Override
  public Scan preScannerOpen(CoprocessorEnvironment e, Scan scan)
      throws IOException {
    requirePermission(TablePermission.Action.READ, e,
        Arrays.asList(scan.getFamilies()));
    return scan;
  }

  @Override
  public void preScannerNext(CoprocessorEnvironment e,
      long scannerId) throws IOException {
    requirePermission(TablePermission.Action.READ, e, null);
  }

  @Override
  public void preScannerClose(CoprocessorEnvironment e, long scannerId)
      throws IOException {
    requirePermission(TablePermission.Action.READ, e, null);
  }
}
