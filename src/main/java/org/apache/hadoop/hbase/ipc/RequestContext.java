package org.apache.hadoop.hbase.ipc;

import org.apache.hadoop.ipc.VersionedProtocol;
import org.apache.hadoop.security.UserGroupInformation;

import java.net.InetAddress;

/**
 * Represents client information (authenticated username, remote address, protocol)
 * for the currently executing request within a RPC server handler thread.  If
 * called outside the context of a RPC request, all values will be
 * <code>null</code>.
 */
public class RequestContext {
  private static ThreadLocal<RequestContext> instance =
      new ThreadLocal<RequestContext>() {
        protected RequestContext initialValue() {
          return new RequestContext(null, null, null);
        }
      };

  public static RequestContext get() {
    return instance.get();
  }

  /**
   * Returns the user credentials associated with the current RPC request or
   * <code>null</code> if no credentials were provided.
   * @return
   */
  public static UserGroupInformation getRequestUser() {
    RequestContext ctx = instance.get();
    if (ctx != null) {
      return ctx.getUser();
    }
    return null;
  }

  /**
   * Initializes the client credentials for the current request.
   * @param user
   * @param remoteAddress
   * @param protocol
   */
  public static void set(UserGroupInformation user,
      InetAddress remoteAddress,
      Class<? extends VersionedProtocol> protocol) {
    RequestContext ctx = instance.get();
    ctx.user = user;
    ctx.remoteAddress = remoteAddress;
    ctx.protocol = protocol;
  }

  /**
   * Clears out the client credentials for a given request.
   */
  public static void clear() {
    RequestContext ctx = instance.get();
    ctx.user = null;
    ctx.remoteAddress = null;
    ctx.protocol = null;
  }

  private UserGroupInformation user;
  private InetAddress remoteAddress;
  private Class<? extends VersionedProtocol> protocol;

  private RequestContext(UserGroupInformation user, InetAddress remoteAddr,
      Class<? extends VersionedProtocol> protocol) {
    this.user = user;
    this.remoteAddress = remoteAddr;
    this.protocol = protocol;
  }

  public UserGroupInformation getUser() {
    return user;
  }

  public InetAddress getRemoteAddress() {
    return remoteAddress;
  }

  public Class<? extends VersionedProtocol> getProtocol() {
    return protocol;
  }
}
