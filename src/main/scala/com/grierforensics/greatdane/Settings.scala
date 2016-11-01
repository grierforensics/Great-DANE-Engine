// Copyright (C) 2016 Grier Forensics. All Rights Reserved.

package com.grierforensics.greatdane

import com.typesafe.config.ConfigFactory

object Settings {
  val config = {
    val cfg = ConfigFactory.load()
    cfg.getConfig("com.grierforensics.greatdane.engine")
  }

  object Default {
    val Port = config.getInt("port")
    val DnsServer = config.getString("dns")
  }
}
