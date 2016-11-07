// Copyright (C) 2016 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import com.typesafe.config.ConfigFactory

object Settings {
  import scala.collection.JavaConverters._

  val config = {
    val cfg = ConfigFactory.load()
    cfg.getConfig("com.grierforensics.greatdane.engine")
  }

  object Default {
    val Port = config.getInt("port")
    val DnsServers = config.getStringList("dns").asScala
  }
}
