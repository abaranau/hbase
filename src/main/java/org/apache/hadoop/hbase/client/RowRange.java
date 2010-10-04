package org.apache.hadoop.hbase.client;

/**
 * Sequential range of rows, such as represented by a {@link Scan} instance.
 */
public interface RowRange {
  /**
   * @return The first row key in the range
   */
  byte [] getStartRow();

  /**
   * @return The row key ending the range (exclusive)
   */
  byte [] getStopRow();
}
