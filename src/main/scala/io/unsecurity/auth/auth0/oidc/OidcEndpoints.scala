package io.unsecurity.auth
package auth0
package oidc

import java.net.URI

import cats.effect.Sync
import io.unsecurity.Unsecurity2
import io.unsecurity.hlinx.HLinx.{HLinx, HNil}
import no.scalabin.http4s.directives.Directive
import org.http4s.{Method, Response, ResponseCookie}
import org.slf4j.{Logger, LoggerFactory}

class Auth0OidcUnsecurity[F[_]: Sync](authConfig: AuthConfig, baseUrl: HLinx[HNil], sessionStore: SessionStore[OidcAuthenticatedUser])
    extends Unsecurity2[F, OidcAuthenticatedUser] {

  private val log: Logger          = LoggerFactory.getLogger(classOf[Auth0OidcUnsecurity[F]])

  override val sc: Auth0OidcSecurityContext[F] = new Auth0OidcSecurityContext[F](authConfig, sessionStore)

  val login =
    unsecure(
      Endpoint(
        method = Method.GET,
        path = baseUrl / "login"
      )
    ).run(
      _ =>
        for {
          returnToUrlParam      <- queryParam("next").map(_.map(URI.create))
          _                     = log.trace("/login returnToUrlParam: {}", returnToUrlParam)
          auth0CallbackUrlParam <- queryParam("auth0Callback").map(_.map(URI.create))
          _                     = log.trace("/login auth0CallbackUrlParam: {}", auth0CallbackUrlParam)
          state                 = sc.randomString(32)
          callbackUrl           = auth0CallbackUrlParam.getOrElse(authConfig.defaultAuth0CallbackUrl)
          returnToUrl           = returnToUrlParam.getOrElse(authConfig.defaultReturnToUrl)
          stateCookie           = sc.Cookies.createStateCookie(secureCookie = callbackUrl.getScheme.equalsIgnoreCase("https"))
          _                     = sessionStore.storeState(stateCookie.content, state, returnToUrl, callbackUrl)
          auth0Url              = sc.createAuth0Url(state, callbackUrl)
          _                     <- break(Redirect(auth0Url).addCookie(stateCookie))
        } yield {
          ()
      }
    )

  val callback =
    unsecure(
      Endpoint(
        method = Method.GET,
        path = baseUrl / "callback"
      )
    ).run(
      _ =>
        for {
          stateCookie   <- cookie(sc.Cookies.Keys.STATE)
          stateParam    <- requiredQueryParam("state")
          xForwardedFor <- requestHeader("X-Forwarded-For")
          state         <- sc.validateState(stateCookie, stateParam, xForwardedFor.map(_.value))
          _             = log.trace("/callback state cookie matches state param")
          codeParam     <- requiredQueryParam("code")
          _             = log.trace("/callback callbackUrl: {}", state.callbackUrl)
          token         <- sc.fetchTokenFromAuth0(codeParam, state.callbackUrl)
          oidcUser      <- sc.verifyTokenAndGetOidcUser(token)
          _             = log.trace("/callback userProfile: {}", oidcUser)
          sessionCookie = sc.Cookies.createSessionCookie(
            secureCookie = state.callbackUrl.getScheme.equalsIgnoreCase("https")
          )
          _ = sessionStore.storeSession(sessionCookie.content, oidcUser)
          returnToUrl = if (sc.isReturnUrlWhitelisted(state.returnToUrl)) {
            state.returnToUrl
          } else {
            log.warn(
              s"/callback returnToUrl (${state.returnToUrl}) not whitelisted; falling back to ${authConfig.defaultReturnToUrl}")
            authConfig.defaultReturnToUrl
          }
          _ = sessionStore.removeState(stateCookie.content)
          _ <- break(
                Redirect(returnToUrl)
                  .addCookie(ResponseCookie(name = sc.Cookies.Keys.STATE, content = "", maxAge = Option(-1)))
                  .addCookie(sessionCookie)
                  .addCookie(
                    sc.Cookies.createXsrfCookie(secureCookie = returnToUrl.getScheme.equalsIgnoreCase("https")))
              )
        } yield {
          ()
      }
    )

  val logout =
    unsecure(
      Endpoint(
        method = Method.GET,
        path = baseUrl / "logout"
      )
    ).run(
      _ =>
        for {
          cookie <- sc.sessionCookie
          _      = sessionStore.removeSession(cookie.content)
          _ <- break(
                Redirect(authConfig.afterLogoutUrl)
                  .addCookie(
                    ResponseCookie(name = sc.Cookies.Keys.K_SESSION_ID, content = "", maxAge = Option(-1))
                  )
                  .addCookie(
                    ResponseCookie(name = sc.Cookies.Keys.XSRF, content = "", maxAge = Option(-1), httpOnly = false)
                  )
              )
        } yield {
          ()
      }
    )

  val endpoints = List(login, callback, logout)

  def break(response: => Response[F]): Directive[F, Response[F]] = {
    Directive.error[F, Response[F]](response)
  }

}
