package io.unsecurity.auth

case class Minutes(asInt: Int) {
  def toSeconds: Int = asInt * 60
}
