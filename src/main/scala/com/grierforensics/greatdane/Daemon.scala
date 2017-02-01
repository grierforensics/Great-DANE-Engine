// Copyright (C) 2017 Grier Forensics. All Rights Reserved.
package com.grierforensics.greatdane

import com.typesafe.scalalogging.LazyLogging

/** "Implements" the necessary methods for Apache commons-daemon's JSVC support
  * See: https://commons.apache.org/proper/commons-daemon/jsvc.html
  */
class Daemon extends LazyLogging {
  var service: Service = _

  /** Create any necessary resources */
  def init(args: Array[String]): Unit = { }

  /** Start daemon
    *
    * Must be started in a separate thread, so `jsvc` and `procrun`
    * can exit, leaving the JVM running in the background.
    */
  def start(): Unit = {
    new Thread() {
      override def run(): Unit = {
        val engine = new Engine(Settings.Default.DnsServers:_*)
        logger.info(s"Using DNS addresses: ${Settings.Default.DnsServers.mkString(", ")}")

        val port = Settings.Default.Port
        val service = new Service(engine, port)
        service.run()
      }
    }.start()
  }

  /** Stop daemon */
  def stop(): Unit = {
    if (service != null) {
      service.stop()
    }
  }

  /** Clean up resources created in `init` */
  def destroy(): Unit = {}
}

object Daemon {

  /** Static Daemon instance used to start/stop Service from different threads.
    *
    * Commons-daemon requires that Daemon be a class instance, hence the static,
    * singleton instance here.
    */
  var daemon: Daemon = _

  def main(args: Array[String]): Unit = {
    if (args.length < 1) {
      println("Usage: greatdaneengine [start|stop]")
      sys.exit(1)
    }

    // Instantiate daemon if first time (e.g. "start"ing service)
    if (daemon == null) {
      daemon = new Daemon()
    }

    args(0) match {
      case "start" => daemon.start()
      case "stop" => daemon.stop()
    }
  }
}
