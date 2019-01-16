package io.unsecurity.auth

import java.net.URI

trait SessionRepo {
  def storeCallbackUrl(id: String, callbackUrl: URI): Unit    = ???
  def storeReturnToUrl(id: String, returnToUrl: String): Unit = ???
  def storeState(id: String, state: State): Unit              = ???
}