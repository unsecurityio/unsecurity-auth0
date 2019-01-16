package io.unsecurity.auth

import java.net.URI

case class AuthConfig(clientId: String,
                      clientSecret: String,
                      authDomain: String,
                      defaultAuth0CallbackUrl: URI,
                      defaultReturnToUrl: URI,
                      returnToUrlDomainWhitelist: List[String],
                      afterLogoutUrl: URI,
                      sessionCookieTtl: Minutes)
