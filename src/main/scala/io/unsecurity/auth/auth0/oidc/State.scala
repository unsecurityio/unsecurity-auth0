package io.unsecurity.auth
package auth0
package oidc

import java.net.URI

case class State(
    state: String,
    returnToUrl: URI,
    callbackUrl: URI
)