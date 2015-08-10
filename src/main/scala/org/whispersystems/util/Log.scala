package org.whispersystems.util

import java.util.logging.{Level, Logger}

object Log {
  val logger = Logger.getLogger("Axolotl.Proto")

  def v[T](fmt: String, ms: T*)  {
    logger.log(Level.FINE, fmt.format(ms : _*))
  }

  def t[T](fmt: String, ms: T*) {
    logger.log(Level.FINEST, fmt.format(ms : _*))
  }
}
