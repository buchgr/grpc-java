/*
 * Copyright 2014, Google Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google Inc. nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package io.grpc.transport.netty;

import static io.netty.channel.ChannelOption.SO_KEEPALIVE;

import com.google.common.base.Preconditions;

import io.grpc.Metadata;
import io.grpc.MethodDescriptor;
import io.grpc.transport.ClientStream;
import io.grpc.transport.ClientStreamListener;
import io.grpc.transport.ClientTransport;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerAdapter;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPromise;
import io.netty.channel.DefaultChannelPromise;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.local.LocalAddress;
import io.netty.channel.local.LocalChannel;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.AsciiString;
import io.netty.handler.codec.http2.DefaultHttp2Connection;
import io.netty.handler.codec.http2.DefaultHttp2FrameReader;
import io.netty.handler.codec.http2.DefaultHttp2FrameWriter;
import io.netty.handler.codec.http2.DefaultHttp2LocalFlowController;
import io.netty.handler.codec.http2.DefaultHttp2StreamRemovalPolicy;
import io.netty.handler.codec.http2.Http2Connection;
import io.netty.handler.codec.http2.Http2FrameLogger;
import io.netty.handler.codec.http2.Http2FrameReader;
import io.netty.handler.codec.http2.Http2FrameWriter;
import io.netty.handler.codec.http2.Http2Headers;
import io.netty.handler.codec.http2.Http2InboundFrameLogger;
import io.netty.handler.codec.http2.Http2OutboundFrameLogger;
import io.netty.handler.codec.http2.Http2StreamRemovalPolicy;
import io.netty.handler.ssl.SslContext;
import io.netty.util.concurrent.DefaultPromise;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.ImmediateEventExecutor;
import io.netty.util.concurrent.Promise;
import io.netty.util.internal.logging.InternalLogLevel;

import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

/**
 * A Netty-based {@link ClientTransport} implementation.
 */
class NettyClientTransport implements ClientTransport {
  private static final Logger log = Logger.getLogger(NettyClientTransport.class.getName());

  private final SocketAddress address;
  private final EventLoopGroup group;
  private final ChannelInitializer<Channel> channelInitializer;
  private final NettyClientHandler handler;
  private final boolean tls;
  private final AsciiString authority;
  // We should not send on the channel until negotiation completes. This is a hard requirement
  // by SslHandler but is appropriate for HTTP/1.1 Upgrade as well.
  private Channel channel;
  private Listener listener;

  private final AtomicBoolean shutdown = new AtomicBoolean();

  private final AtomicBoolean terminated = new AtomicBoolean();

  private Future registrationFuture;

  /**
   * Whether the transport started or failed during starting. Only transitions to true. When
   * changed, this.notifyAll() must be called.
   */
//  private volatile boolean started;
//  /** Guaranteed to be true when RUNNING. */
//  private volatile boolean negotiationComplete;
//  /** Whether the transport started shutting down. */
//  @GuardedBy("this")
//  private boolean shutdown;
//  private Throwable shutdownCause;
//  /** Whether the transport completed shutting down. */
//  @GuardedBy("this")
//  private boolean terminated;

  NettyClientTransport(SocketAddress address, NegotiationType negotiationType,
      EventLoopGroup group, SslContext sslContext) {
    Preconditions.checkNotNull(negotiationType, "negotiationType");
    this.address = Preconditions.checkNotNull(address, "address");
    this.group = Preconditions.checkNotNull(group, "group");
    registrationFuture = new DefaultPromise(group.next());

    InetSocketAddress inetAddress = null;
    if (address instanceof InetSocketAddress) {
      inetAddress = (InetSocketAddress) address;
      authority = new AsciiString(inetAddress.getHostString() + ":" + inetAddress.getPort());
    } else if (address instanceof LocalAddress) {
      authority = new AsciiString(address.toString());
      Preconditions.checkArgument(negotiationType != NegotiationType.TLS,
          "TLS not supported for in-process transport");
    } else {
      throw new IllegalStateException("Unknown socket address type " + address.toString());
    }

    DefaultHttp2StreamRemovalPolicy streamRemovalPolicy = new DefaultHttp2StreamRemovalPolicy();
    handler = newHandler(streamRemovalPolicy);
    channelInitializer = channelInitializer(handler, streamRemovalPolicy, inetAddress, negotiationType, sslContext);
    tls = NegotiationType.TLS.equals(negotiationType);
  }

  private static class BufferUntilChannelActiveHandler extends ChannelHandlerAdapter {
    private final Queue<ChannelWrite> writes = new ArrayDeque<ChannelWrite>();

    @Override
    public void write(ChannelHandlerContext ctx, Object msg, ChannelPromise promise) throws Exception {
      writes.add(new ChannelWrite(msg, promise));
      tryFlush(ctx);
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) {
      tryFlush(ctx);
      ctx.fireChannelActive();
    }

    @Override
    public void channelWritabilityChanged(ChannelHandlerContext ctx) throws Exception {
      tryFlush(ctx);
      ctx.fireChannelWritabilityChanged();
    }

    @Override
    public void flush(ChannelHandlerContext ctx) {
      tryFlush(ctx);
    }

    private void tryFlush(final ChannelHandlerContext ctx) {
      final Channel ch = ctx.channel();
      if (ch.isActive() && ch.isWritable()) {
        while (!writes.isEmpty() && ch.isActive() && ch.isWritable()) {
          ChannelWrite write = writes.remove();
          ctx.writeAndFlush(write.msg, write.promise);
        }
//        if (ch.pipeline().context(this) != null && writes.isEmpty()) {
//          ch.pipeline().remove(this);
//        }
      }
    }

    private static final class ChannelWrite {
      final Object msg;
      final ChannelPromise promise;

      ChannelWrite(Object msg, ChannelPromise promise) {
        this.msg = msg;
        this.promise = promise;
      }
    }
  }

  @Override
  public void start(Listener transportListener) {
    listener = Preconditions.checkNotNull(transportListener, "listener");
    Bootstrap b = new Bootstrap();
    b.group(group);
    if (address instanceof LocalAddress) {
      b.channel(LocalChannel.class);
    } else {
      b.channel(NioSocketChannel.class);
      b.option(SO_KEEPALIVE, true);
    }
    b.handler(new ChannelInitializer<Channel>() {
      @Override
      protected void initChannel(Channel ch) throws Exception {
        ch.pipeline().addLast(handler);
        ch.pipeline().addLast(new BufferUntilChannelActiveHandler());

        ((Promise)registrationFuture).trySuccess(null);
      }
    });

    // Connect to the server
    ChannelFuture connectFuture = b.connect(address);
    channel = connectFuture.channel();
    connectFuture.addListener(new ChannelFutureListener() {
      @Override
      public void operationComplete(ChannelFuture future) throws Exception {
        if (!future.isSuccess()) {
          // The connection attempt failed.
          notifyTerminated(future.cause());
          return;
        }
      }
    });
    // Handle transport shutdown when the channel is closed.
    channel.closeFuture().addListener(new ChannelFutureListener() {
      @Override
      public void operationComplete(ChannelFuture future) throws Exception {
        if (!future.isSuccess()) {
          // The close failed. Just notify that transport shutdown failed.
          notifyTerminated(future.cause());
          return;
        }

        if (handler.connectionError() != null) {
          // The handler encountered a connection error.
          notifyTerminated(handler.connectionError());
        } else {
          // Normal termination of the connection.
          notifyTerminated(null);
        }
      }
    });

    registrationFuture.awaitUninterruptibly();
  }

  @Override
  public ClientStream newStream(final MethodDescriptor<?, ?> method, final Metadata.Headers headers,
      final ClientStreamListener listener) {
    Preconditions.checkNotNull(method, "method");
    Preconditions.checkNotNull(headers, "headers");
    Preconditions.checkNotNull(listener, "listener");

    // Create the stream.
    final NettyClientStream stream = new NettyClientStream(listener, channel, handler);

    // Convert the headers into Netty HTTP/2 headers.
    AsciiString defaultPath = new AsciiString("/" + method.getName());
    Http2Headers http2Headers = Utils.convertClientHeaders(headers, tls, defaultPath, authority);

    // Write the request and await creation of the stream.
    channel.writeAndFlush(new CreateStreamCommand(http2Headers, stream));

    return stream;
  }


//  @Override
//  public void shutdown() {
//    notifyShutdown(null);
//    // Notifying of termination is automatically done when the channel closes.
//    if (channel != null && channel.isOpen()) {
//      channel.close();
//    }
//  }

//  /**
//   * Waits until started. Does not throw an exception if the transport has now failed.
//   */
//  private void awaitStarted() {
//    if (!started) {
//      try {
//        synchronized (this) {
//          while (!started) {
//            wait();
//          }
//        }
//      } catch (InterruptedException ex) {
//        Thread.currentThread().interrupt();
//        throw new RuntimeException("Interrupted while waiting for transport to start", ex);
//      }
//    }
//  }
//
//  private synchronized void notifyStarted() {
//    started = true;
//    notifyAll();
//  }
//
//  private void notifyShutdown(Throwable t) {
//    if (t != null) {
//      log.log(Level.SEVERE, "Transport failed", t);
//    }
//    boolean notifyShutdown;
//    synchronized (this) {
//      notifyShutdown = !shutdown;
//      if (!shutdown) {
//        shutdownCause = t;
//        shutdown = true;
//        notifyStarted();
//      }
//    }
//    if (notifyShutdown) {
//      listener.transportShutdown();
//    }
//  }
//
//  private void notifyTerminated(Throwable t) {
//    notifyShutdown(t);
//    boolean notifyTerminated;
//    synchronized (this) {
//      notifyTerminated = !terminated;
//      terminated = true;
//    }
//    if (notifyTerminated) {
//      listener.transportTerminated();
//    }
//  }


  @Override
  public void shutdown() {
    notifyShutdown(null);
    // Notifying of termination is automatically
    // done when the channel closes.
    if (channel != null && channel.isOpen()) {
      channel.close();
    }
  }

  private void notifyShutdown(Throwable t) {
    if (t != null) {
      log.log(Level.SEVERE, "Transport failed", t);
    }

    if (shutdown.compareAndSet(false, true)) {
      listener.transportShutdown();
    }
  }

  private void notifyTerminated(Throwable t) {
    notifyShutdown(t);

    if (terminated.compareAndSet(false, true)) {
      listener.transportTerminated();
    }
  }

  private static ChannelInitializer<Channel> channelInitializer(NettyClientHandler handler,
                                                                DefaultHttp2StreamRemovalPolicy streamRemovalPolicy,
                                                                InetSocketAddress inetAddress,
                                                                NegotiationType negotiationType,
                                                                SslContext sslContext) {
    switch (negotiationType) {
      case PLAINTEXT:
        return Http2ChannelInitializer.plaintext(handler);
      case PLAINTEXT_UPGRADE:
        return Http2ChannelInitializer.plaintextUpgrade(handler);
      case TLS:
        if (sslContext == null) {
          try {
            sslContext = SslContext.newClientContext();
          } catch (SSLException ex) {
            throw new RuntimeException(ex);
          }
        }
        // TODO(ejona86): specify allocator. The method currently ignores it though.
        SSLEngine sslEngine
                = sslContext.newEngine(null, inetAddress.getHostString(), inetAddress.getPort());
        SSLParameters sslParams = new SSLParameters();
        sslParams.setEndpointIdentificationAlgorithm("HTTPS");
        sslEngine.setSSLParameters(sslParams);
        return Http2ChannelInitializer.tls(sslEngine, streamRemovalPolicy, handler);
      default:
        throw new IllegalArgumentException("Unsupported negotiationType: " + negotiationType);
    }
  }

  private static NettyClientHandler newHandler(Http2StreamRemovalPolicy streamRemovalPolicy) {
    Http2Connection connection =
        new DefaultHttp2Connection(false, streamRemovalPolicy);
    Http2FrameReader frameReader = new DefaultHttp2FrameReader();
    Http2FrameWriter frameWriter = new DefaultHttp2FrameWriter();

    Http2FrameLogger frameLogger = new Http2FrameLogger(InternalLogLevel.DEBUG);
    frameReader = new Http2InboundFrameLogger(frameReader, frameLogger);
    frameWriter = new Http2OutboundFrameLogger(frameWriter, frameLogger);

    DefaultHttp2LocalFlowController inboundFlow =
        new DefaultHttp2LocalFlowController(connection, frameWriter);
    return new NettyClientHandler(connection, frameReader, frameWriter, inboundFlow);
  }
}
