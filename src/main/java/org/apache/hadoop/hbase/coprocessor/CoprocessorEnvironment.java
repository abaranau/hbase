package org.apache.hadoop.hbase.coprocessor;

import java.io.IOException;

import org.apache.hadoop.hbase.client.HTableInterface;
import org.apache.hadoop.hbase.regionserver.HRegion;
import org.apache.hadoop.hbase.regionserver.RegionServerServices;

/**
 * Coprocessor environment state.
 */
public interface CoprocessorEnvironment {

  /** @return the Coprocessor interface version */
  public int getVersion();

  /** @return the HBase version as a string (e.g. "0.21.0") */
  public String getHBaseVersion();

  /** @return the region associated with this coprocessor */
  public HRegion getRegion();

  /** @return reference to the region server services */
  public RegionServerServices getRegionServerServices();

  /**
   * @return an interface for accessing the given table
   * @throws IOException
   */
  public HTableInterface getTable(byte[] tableName) throws IOException;

  // environment variables

  /**
   * Get an environment variable
   * @param key the key
   * @return the object corresponding to the environment variable, if set
   */
  public Object get(Object key);

  /**
   * Set an environment variable
   * @param key the key
   * @param value the value
   */
  public void put(Object key, Object value);

  /**
   * Remove an environment variable
   * @param key the key
   * @return the object corresponding to the environment variable, if set
   */
  public Object remove(Object key);

}
