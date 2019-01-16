package io.unsecurity.auth.oidc

import java.net.URI
import java.security.SecureRandom

import cats.effect.Sync
import com.auth0.client.auth.AuthAPI
import io.unsecurity.{Unsecurity2, UnsecurityOps}
import io.unsecurity.auth.AuthConfig
import io.unsecurity.hlinx.HLinx.Root
import no.scalabin.http4s.directives.Directive
import org.apache.commons.codec.binary.Hex
import org.http4s.{Method, Response, ResponseCookie}
import org.slf4j.{Logger, LoggerFactory}

case class OidcEndpoints[F[_]: Sync, U](
    unsecurity2: Unsecurity2[F, U],
    authConfig: AuthConfig,
    stateStore: StateStore,
    cookieName: String
) {
  val log: Logger = LoggerFactory.getLogger(classOf[OidcEndpoints[F, U]])

  import unsecurity2._

  val login =
    unsecure(
      Endpoint(
        method = Method.GET,
        path = Root / "login"
      )
    ).run(
      _ =>
        for {
          returnToUrl      <- queryParam("next").map(_.map(URI.create))
          _                = log.trace("/login returnToUrlParam: {}", returnToUrl)
          auth0CallbackUrl <- queryParam("auth0Callback").map(_.map(URI.create))
          _                = log.trace("/login auth0CallbackUrl: {}", auth0CallbackUrl)
          state            = randomString(32)
          callbackUrl      = auth0CallbackUrl.getOrElse(authConfig.defaultAuth0CallbackUrl)
          stateCookie      = Cookies.createStateCookie(secureCookie = callbackUrl.getScheme.equalsIgnoreCase("https"))
          _ = stateStore.store(stateRef = stateCookie.content,
                               state = state,
                               returnToUrl = returnToUrl,
                               callbackUrl = callbackUrl)
          auth0Url = createAuth0Url(state, callbackUrl)
          _        <- break(Redirect(auth0Url).addCookie(stateCookie))
        } yield {
          ()
      }
    )

  val endpoints = List(login)

  def break(response: => Response[F]): Directive[F, Response[F]] = {
    Directive.failure[F, Response[F]](response)
  }

  private def randomString(lengthInBytes: Int): String = {
    val secrand: SecureRandom  = new SecureRandom()
    val byteArray: Array[Byte] = Array.fill[Byte](lengthInBytes)(0)
    secrand.nextBytes(byteArray)

    Hex.encodeHexString(byteArray)
  }

  def createAuth0Url(state: String, auth0CallbackUrl: URI): String = {
    new AuthAPI(authConfig.authDomain, authConfig.clientId, authConfig.clientSecret)
      .authorizeUrl(auth0CallbackUrl.toString)
      .withScope("openid profile email")
      .withState(state)
      .withResponseType("code")
      .build()
  }

  object Cookies {

    object Keys {
      val STATE: String        = "statecookie"
      val K_SESSION_ID: String = cookieName
      val XSRF: String         = "xsrf-token"
    }

    def createXsrfCookie(secureCookie: Boolean): ResponseCookie = {
      val xsrfToken: String = randomString(32)
      log.trace("xsrfToken: {}", xsrfToken)

      ResponseCookie(
        name = Keys.XSRF,
        content = xsrfToken,
        secure = secureCookie,
        httpOnly = false,
        path = Some("/"),
        maxAge = Some(authConfig.sessionCookieTtl.toSeconds)
      )
    }

    def createSessionCookie(secureCookie: Boolean): ResponseCookie = {
      ResponseCookie(
        name = Keys.K_SESSION_ID,
        content = randomString(64),
        secure = secureCookie,
        path = Some("/"),
        httpOnly = true,
        maxAge = Some(authConfig.sessionCookieTtl.toSeconds)
      )
    }

    def createStateCookie(secureCookie: Boolean): ResponseCookie = {
      val stateCookieRef: String = randomString(16)
      log.trace("stateCookieRef: {}", stateCookieRef)

      ResponseCookie(name = Cookies.Keys.STATE, content = stateCookieRef, secure = secureCookie)
    }
  }

}

trait StateStore {
  def store(stateRef: String, state: State): Unit
  def store(stateRef: String, state: String, returnToUrl: Option[URI], callbackUrl: URI): Unit
}

case class State(
    state: String,
    returnToUrl: Option[String],
    callbackUrl: URI
)
