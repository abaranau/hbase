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

import com.google.common.collect.Maps;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.hadoop.hbase.util.Bytes;
import org.apache.hadoop.io.VersionedWritable;

import java.io.DataInput;
import java.io.DataOutput;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

/**
 * Represents an authorization for access for the given actions, optionally
 * restricted to the given column family, over the given table.  If the family
 * property is <code>null</code>, it implies full table access.
 */
public class TablePermission extends VersionedWritable {
  private static Log LOG = LogFactory.getLog(TablePermission.class);
  private static final byte VERSION = 0;
  public enum Action {
    READ('R'), WRITE('W');

    private byte code;
    Action(char code) {
      this.code = (byte)code;
    }

    public byte code() { return code; }
  }

  private static Map<Byte,Action> ACTION_BY_CODE = Maps.newHashMap();
  static {
    for (Action a : Action.values()) {
      ACTION_BY_CODE.put(a.code(), a);
    }
  }

  private byte[] table;
  private byte[] family;
  private Action[] actions;

  /** Nullary constructor for Writable, do not use */
  public TablePermission() {
    super();
  }

  /**
   * Constructor
   * @param table the table
   * @param family the family, can be null if a global permission on the table
   * @param assigned the list of allowed actions
   */
  public TablePermission(byte[] table, byte[] family, Action... assigned) {
    super();
    this.table = table;
    this.family = family;
    if (assigned != null && assigned.length > 0) {
      actions = Arrays.copyOf(assigned, assigned.length);
    }
  }

  /**
   * Constructor
   * @param table the table
   * @param family the family, can be null if a global permission on the table
   * @param actionCodes the list of allowed action codes
   */
  public TablePermission(byte[] table, byte[] family, byte[] actionCodes) {
    super();
    this.table = table;
    this.family = family;

    if (actionCodes != null) {
      this.actions = new Action[actionCodes.length];
      for (int i=0; i<actionCodes.length; i++) {
        byte b = actionCodes[i];
        Action a = ACTION_BY_CODE.get(b);
        if (a == null) {
          LOG.error("Ignoring unknown action code '"+
              Bytes.toStringBinary(new byte[]{b})+"'");
          continue;
        }
        this.actions[i] = a;
      }
    }
  }

  public byte[] getTable() {
    return table;
  }

  public byte[] getFamily() {
    return family;
  }

  public Action[] getActions() {
    return actions;
  }

  /**
   * Checks that a given table operation is authorized by this permission
   * instance.
   *
   * @param table
   * @param family
   * @param action
   * @return
   */
  public boolean implies(byte[] table, byte[] family, Action action) {
    if (!Bytes.equals(this.table, table)) {
      return false;
    }

    if (this.family != null &&
        (family == null ||
         !Bytes.equals(this.family, family))) {
      return false;
    }

    if (this.actions != null) {
      for (Action a : this.actions) {
        if (a == action) {
          return true;
        }
      }
    }

    return false;
  }

  public boolean equals(Object obj) {
    if (!(obj instanceof TablePermission)) {
      return false;
    }
    TablePermission other = (TablePermission)obj;

    if (!(Bytes.equals(table, other.getTable()) &&
        ((family == null && other.getFamily() == null) ||
         Bytes.equals(family, other.getFamily())
       ))) {
      return false;
    }

    // check actions
    if (actions == null && other.getActions() == null) {
      return true;
    } else if (actions != null && other.getActions() != null) {
      Action[] otherActions = other.getActions();
      if (actions.length != otherActions.length) {
        return false;
      }

      outer:
      for (Action a : actions) {
        for (Action oa : otherActions) {
          if (a == oa) continue outer;
        }
        return false;
      }
      return true;
    }

    return false;
  }

  public String toString() {
    StringBuilder str = new StringBuilder("[Permission: ")
        .append("table=").append(Bytes.toString(table))
        .append(", family=").append(Bytes.toString(family))
        .append(", actions=");
    if (actions != null) {
      for (int i=0; i<actions.length; i++) {
        if (i > 0)
          str.append(",");
        if (actions[i] != null)
          str.append(actions[i].toString());
        else
          str.append("NULL");
      }
    }
    str.append("]");

    return str.toString();
  }

  /** @return the object version number */
  public byte getVersion() {
    return VERSION;
  }

  @Override
  public void readFields(DataInput in) throws IOException {
    super.readFields(in);
    table = Bytes.readByteArray(in);
    if (in.readBoolean()) {
      family = Bytes.readByteArray(in);
    }
    int length = (int)in.readByte();
    if (length > 0) {
      actions = new Action[length];
      for (int i = 0; i < length; i++) {
        byte b = in.readByte();
        Action a = ACTION_BY_CODE.get(b);
        if (a == null) {
          LOG.error("Ignoring unknown action code '"+
              Bytes.toStringBinary(new byte[]{b})+"'");
          continue;
        }
        this.actions[i] = a;
      }
    } else {
      actions = new Action[0];
    }
  }

  @Override
  public void write(DataOutput out) throws IOException {
    super.write(out);
    Bytes.writeByteArray(out, table);
    out.writeBoolean(family != null);
    if (family != null) {
      Bytes.writeByteArray(out, family);
    }
    out.writeByte(actions != null ? actions.length : 0);
    if (actions != null) {
      for (Action a: actions) {
        out.writeByte(a.code());
      }
    }
  }
}
