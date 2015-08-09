package org.whispersystems

object Util {
  def emplace(target: Array[Byte], to: Int, source: Array[Byte], from: Int, length: Int): Array[Byte] =
    target.patch(to, source.slice(from, from + length), length)
}

