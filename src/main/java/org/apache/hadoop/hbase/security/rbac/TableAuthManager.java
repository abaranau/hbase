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
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.hbase.zookeeper.ZooKeeperWatcher;
import org.apache.hadoop.security.UserGroupInformation;
import org.apache.zookeeper.KeeperException;

import java.io.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListMap;

/**
 * Performs authorization checks for a given user's assigned permissions
 */
public class TableAuthManager {
  private static Log LOG = LogFactory.getLog(TableAuthManager.class);

  private static TableAuthManager instance;

  private ConcurrentSkipListMap<byte[], ListMultimap<String,TablePermission>> TABLE_USER_CACHE =
      new ConcurrentSkipListMap<byte[], ListMultimap<String,TablePermission>>(Bytes.BYTES_COMPARATOR);

  private ConcurrentSkipListMap<byte[], ListMultimap<String,TablePermission>> TABLE_GROUP_CACHE =
      new ConcurrentSkipListMap<byte[], ListMultimap<String,TablePermission>>(Bytes.BYTES_COMPARATOR);

  private Configuration conf;
  private ZKPermissionWatcher zkperms;

  private TableAuthManager(ZooKeeperWatcher watcher, Configuration conf) {
    this.conf = conf;
    this.zkperms = new ZKPermissionWatcher(watcher, this, conf);
    try {
      this.zkperms.start();
    } catch (KeeperException ke) {
      LOG.error("ZooKeeper initialization failed", ke);
    }
  }

  public ZKPermissionWatcher getZKPermissionWatcher() {
    return this.zkperms;
  }

  public void refreshCacheFromWritable(byte[] table, byte[] data) throws IOException {
    DataInput in = new DataInputStream( new ByteArrayInputStream(data) );
    ListMultimap<String,TablePermission> perms = AccessControlLists.readPermissions(in, conf);
    cache(table, perms);
  }

  /**
   * Updates the internal permissions cache for a single table, splitting
   * the permissions listed into separate caches for users and groups to optimize
   * group lookups.
   * 
   * @param table
   * @param tablePerms
   */
  private void cache(byte[] table,
      ListMultimap<String,TablePermission> tablePerms) {
    // split user from group assignments so we don't have to prepend the group
    // prefix every time we query for groups
    ListMultimap<String,TablePermission> userPerms = ArrayListMultimap.create();
    ListMultimap<String,TablePermission> groupPerms = ArrayListMultimap.create();

    if (tablePerms != null) {
      for (Map.Entry<String,TablePermission> entry : tablePerms.entries()) {
        if (entry.getKey().startsWith(AccessControlLists.GROUP_PREFIX)) {
          groupPerms.put(
              entry.getKey().substring(AccessControlLists.GROUP_PREFIX.length()),
              entry.getValue());
        } else {
          userPerms.put(entry.getKey(), entry.getValue());
        }
      }
      TABLE_GROUP_CACHE.put(table, groupPerms);
      TABLE_USER_CACHE.put(table, userPerms);
    }
  }

  private List<TablePermission> getUserPermissions(String username, byte[] table) {
    ListMultimap<String, TablePermission> tablePerms = TABLE_USER_CACHE.get(table);
    if (tablePerms != null) {
      return tablePerms.get(username);
    }

    return null;
  }

  private List<TablePermission> getGroupPermissions(String groupName, byte[] table) {
    ListMultimap<String, TablePermission> tablePerms = TABLE_GROUP_CACHE.get(table);
    if (tablePerms != null) {
      return tablePerms.get(groupName);
    }

    return null;
  }

  public boolean authorize(List<TablePermission> perms, byte[] table, byte[] family,
      TablePermission.Action action) {
    if (perms != null) {
      for (TablePermission p : perms) {
        if (p.implies(table, family, action)) {
          return true;
        }
      }
    } else if (LOG.isDebugEnabled()) {
      LOG.debug("No permissions found for table="+Bytes.toStringBinary(table));
    }

    return false;
  }

  /**
   * Checks authorization to a given table and column family for a user, based on the
   * stored user permissions.
   *
   * @param username
   * @param table
   * @param family
   * @param action
   * @return
   */
  public boolean authorizeUser(String username, byte[] table, byte[] family,
      TablePermission.Action action) {
    return authorize(getUserPermissions(username, table), table, family, action);
  }

  /**
   * Checks authorization to a given table and column family for a group, based
   * on the stored permissions. 
   * @param groupName
   * @param table
   * @param family
   * @param action
   * @return
   */
  public boolean authorizeGroup(String groupName, byte[] table, byte[] family,
      TablePermission.Action action) {
    return authorize(getGroupPermissions(groupName, table), table, family, action);
  }

  public boolean authorize(UserGroupInformation user, byte[] table, byte[] family,
      TablePermission.Action action) {
    if (authorizeUser(user.getUserName(), table, family, action)) {
      return true;
    }

    String[] groups = user.getGroupNames();
    if (groups != null) {
      for (String group : groups) {
        if (authorizeGroup(group, table, family, action)) {
          return true;
        }
      }
    }
    return false;
  }

  public void remove(byte[] table) {
    TABLE_USER_CACHE.remove(table);
    TABLE_GROUP_CACHE.remove(table);
  }

  /**
   * Overwrites the existing permission set for a given user for a table, and
   * triggers an update for zookeeper synchronization.
   * @param username
   * @param table
   * @param perms
   */
  public void setUserPermissions(String username, byte[] table,
      List<TablePermission> perms) {
    ListMultimap<String,TablePermission> tablePerms = TABLE_USER_CACHE.get(table);
    if (tablePerms == null) {
      tablePerms = ArrayListMultimap.create();
      TABLE_USER_CACHE.put(table, tablePerms);
    }
    tablePerms.replaceValues(username, perms);
    writeToZooKeeper(table, tablePerms, TABLE_GROUP_CACHE.get(table));
  }

  /**
   * Overwrites the existing permission set for a group and triggers an update
   * for zookeeper synchronization.
   * @param group
   * @param table
   * @param perms
   */
  public void setGroupPermissions(String group, byte[] table,
      List<TablePermission> perms) {
    ListMultimap<String,TablePermission> tablePerms = TABLE_GROUP_CACHE.get(table);
    if (tablePerms == null) {
      tablePerms = ArrayListMultimap.create();
      TABLE_GROUP_CACHE.put(table, tablePerms);
    }
    tablePerms.replaceValues(group, perms);
    writeToZooKeeper(table, TABLE_USER_CACHE.get(table), tablePerms);
  }

  public void writeToZooKeeper(byte[] table,
      ListMultimap<String,TablePermission> userPerms,
      ListMultimap<String,TablePermission> groupPerms) {
    ListMultimap<String,TablePermission> tmp = ArrayListMultimap.create();
    if (userPerms != null) {
      tmp.putAll(userPerms);
    }
    if (groupPerms != null) {
      for (String group : groupPerms.keySet()) {
        tmp.putAll(AccessControlLists.GROUP_PREFIX + group,
            groupPerms.get(group));
      }
    }
    byte[] serialized = AccessControlLists.writePermissionsAsBytes(tmp, conf);
    zkperms.writeToZookeeper(Bytes.toString(table), serialized);
  }

  static Map<ZooKeeperWatcher,TableAuthManager> managerMap = 
    new HashMap<ZooKeeperWatcher,TableAuthManager>();

  public synchronized static TableAuthManager get(
      ZooKeeperWatcher watcher, Configuration conf) {
    instance = managerMap.get(watcher);
    if (instance == null) {
      instance = new TableAuthManager(watcher, conf);
      managerMap.put(watcher, instance);
    }
    return instance;
  }
}
