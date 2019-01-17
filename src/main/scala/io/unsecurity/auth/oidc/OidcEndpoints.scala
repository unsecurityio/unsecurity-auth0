package io.unsecurity.auth.oidc

import java.net.URI
import java.security.SecureRandom
import java.security.interfaces.RSAPublicKey
import java.util.concurrent.TimeUnit

import cats.effect.Sync
import com.auth0.client.auth.AuthAPI
import com.auth0.jwk.{GuavaCachedJwkProvider, UrlJwkProvider}
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.auth0.jwt.interfaces.DecodedJWT
import io.circe.parser.{decode => cDecode}
import io.circe.{Decoder, Encoder, Json}
import io.unsecurity.Unsecurity2
import io.unsecurity.auth.AuthConfig
import io.unsecurity.auth.oidc.Jwt.JwtHeader
import io.unsecurity.hlinx.HLinx.{HLinx, HNil}
import no.scalabin.http4s.directives.Directive
import okhttp3._
import okio.ByteString
import org.apache.commons.codec.binary.Hex
import org.http4s.{Method, RequestCookie, Response, ResponseCookie, Status}
import org.slf4j.{Logger, LoggerFactory}
import unsecurity.auth0.oidc.OidcAuthenticatedUser

case class OidcEndpoints[F[_]: Sync, U](
    unsecurity2: Unsecurity2[F, U],
    authConfig: AuthConfig,
    baseUrl: HLinx[HNil],
    stateStore: StateStore,
    cookieName: String
) {
  val log: Logger          = LoggerFactory.getLogger(classOf[OidcEndpoints[F, U]])
  val client: OkHttpClient = new OkHttpClient

  import unsecurity2._

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
          state                 = randomString(32)
          callbackUrl           = auth0CallbackUrlParam.getOrElse(authConfig.defaultAuth0CallbackUrl)
          returnToUrl           = returnToUrlParam.getOrElse(authConfig.defaultReturnToUrl)
          stateCookie           = Cookies.createStateCookie(secureCookie = callbackUrl.getScheme.equalsIgnoreCase("https"))
          _                     = stateStore.storeState(stateCookie.content, state, returnToUrl, callbackUrl)
          auth0Url              = createAuth0Url(state, callbackUrl)
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
          stateCookie   <- cookie(Cookies.Keys.STATE)
          stateParam    <- requiredQueryParam("state")
          xForwardedFor <- requestHeader("X-Forwarded-For")
          state         <- validateState(stateCookie, stateParam, xForwardedFor.map(_.value))
          _             = log.trace("/callback state cookie matches state param")
          codeParam     <- requiredQueryParam("code")
          _             = log.trace("/callback callbackUrl: {}", state.callbackUrl)
          token         <- fetchTokenFromAuth0(codeParam, state.callbackUrl)
          oidcUser      <- verifyTokenAndGetOidcUser(token)
          _             = log.trace("/callback userProfile: {}", oidcUser)
          sessionCookie = Cookies.createSessionCookie(
            secureCookie = state.callbackUrl.getScheme.equalsIgnoreCase("https"))
          _ = stateStore.storeSession(sessionCookie.content, oidcUser)
          returnToUrl = if (isReturnUrlWhitelisted(state.returnToUrl)) {
            state.returnToUrl
          } else {
            log.warn(s"/callback returnToUrl (${state.returnToUrl}) not whitelisted; falling back to ${authConfig.defaultReturnToUrl}")
            authConfig.defaultReturnToUrl
          }
          _ = stateStore.removeState(stateCookie.content)
          _ <- break(
                Redirect(returnToUrl)
                  .addCookie(ResponseCookie(name = Cookies.Keys.STATE, content = "", maxAge = Option(-1)))
                  .addCookie(sessionCookie)
                  .addCookie(Cookies.createXsrfCookie(secureCookie = returnToUrl.getScheme.equalsIgnoreCase("https")))
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
          cookie <- sessionCookie
          _      = stateStore.removeSession(cookie.content)
          _ <- break(
                Redirect(authConfig.afterLogoutUrl)
                  .addCookie(
                    ResponseCookie(name = Cookies.Keys.K_SESSION_ID, content = "", maxAge = Option(-1))
                  )
                  .addCookie(
                    ResponseCookie(name = Cookies.Keys.XSRF, content = "", maxAge = Option(-1), httpOnly = false)
                  )
              )
        } yield {
          ()
      }
    )

  val endpoints = List(login, callback, logout)

  def isReturnUrlWhitelisted(uri: URI): Boolean = {
    authConfig.returnToUrlDomainWhitelist.contains(uri.getHost)
  }

  def break(response: => Response[F]): Directive[F, Response[F]] = {
    Directive.error[F, Response[F]](response)
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

  def validateState(stateCookie: RequestCookie, state: String, xForwardedFor: Option[String]): Directive[F, State] = {
    stateStore.getState(stateCookie.content) match {
      case None =>
        log.error(s"Invalid state, possible CSRF-attack on login. X-Forwarded-For: ${xForwardedFor.getOrElse("")}")
        BadRequest("Invalid state, possible csrf-attack")
      case Some(sessionState) =>
        if (state == sessionState.state) {
          Directive.success(sessionState)
        } else {
          log.error(
            s"State values does not match, possible XSRF-attack! X-Forwarded-For: ${xForwardedFor.getOrElse("")} "
          )
          BadRequest("Illegal state value")
        }
    }
  }

  def sessionCookie: Directive[F, RequestCookie] = {
    for {
      cookies <- requestCookies()
      cookie <- cookies
                 .find(c => c.name == cookieName)
                 .map(c => Directive.success(c))
                 .getOrElse(
                   Directive.failure(ResponseJson("Session cookie not found. Please login", Status.Unauthorized))
                 )
    } yield {
      cookie
    }
  }

  case class TokenRequest(grantType: String, clientId: String, clientSecret: String, code: String, redirectUri: URI)
  import io.circe.syntax._

  object TokenRequest {
    implicit val tokenRequestEncoder: Encoder[TokenRequest] = Encoder { tr =>
      Json.obj(
        "grant_type" := tr.grantType,
        "client_id" := tr.clientId,
        "client_secret" := tr.clientSecret,
        "code" := tr.code,
        "redirect_uri" := tr.redirectUri.toString
      )
    }
  }

  case class TokenResponse(accessToken: String, expiresIn: Long, idToken: String, tokenType: String)
  object TokenResponse {
    implicit val tokenResponseDecoder: Decoder[TokenResponse] = Decoder { c =>
      for {
        accessToken <- c.downField("access_token").as[String]
        expiresIn   <- c.downField("expires_in").as[Long]
        idToken     <- c.downField("id_token").as[String]
        tokenType   <- c.downField("token_type").as[String]
      } yield {
        TokenResponse(
          accessToken,
          expiresIn,
          idToken,
          tokenType
        )
      }
    }
  }

  def fetchTokenFromAuth0(code: String, auth0CallbackUrl: URI): Directive[F, TokenResponse] = {
    val tokenUrl: String         = s"https://${authConfig.authDomain}/oauth/token"
    val jsonMediaType: MediaType = MediaType.parse("application/json; charset=utf-8")
    val payload: String = TokenRequest(grantType = "authorization_code",
                                       clientId = authConfig.clientId,
                                       clientSecret = authConfig.clientSecret,
                                       code = code,
                                       redirectUri = auth0CallbackUrl).asJson.noSpaces
    val req: Request = new okhttp3.Request.Builder()
      .url(tokenUrl)
      .post(RequestBody.create(jsonMediaType, payload))
      .build()

    val resp              = client.newCall(req).execute
    val responseCode: Int = resp.code()
    val body: String      = resp.body.string
    resp.body.close()

    if (responseCode == 200) {
      cDecode[TokenResponse](body) match {
        case Right(token) => Directive.success(token)
        case Left(e) =>
          log.error("Error parsing token from auth0 {}. Payload : {}", List(e, body): _*)
          InternalServerError(Json.obj("msg" := "Error parsing token from auth0"))
      }
    } else {
      log.error("Invalid response from auth0, got ({}) {}", responseCode, body)
      InternalServerError(Json.obj("msg" := "Invalid response from IDP"))
    }
  }

  def verifyTokenAndGetOidcUser(tokenResponse: TokenResponse): Directive[F, OidcAuthenticatedUser] = {

    def decodeBase64(value: String): String = ByteString.decodeBase64(value).utf8()

    val numberOfKeys = 10

    val provider: UrlJwkProvider                       = new UrlJwkProvider(s"https://${authConfig.authDomain}/.well-known/jwks.json")
    val cachedProvider                                 = new GuavaCachedJwkProvider(provider, numberOfKeys, 5L, TimeUnit.HOURS)
    val decodedJwt: DecodedJWT                         = JWT.decode(tokenResponse.idToken)
    val decodedHeaderString                            = decodeBase64(decodedJwt.getHeader)
    val decodedEitherHeader: Either[String, JwtHeader] = cDecode[JwtHeader](decodedHeaderString).left.map(_.getMessage)

    val eitherUser: Either[String, OidcAuthenticatedUser] = for {
      header    <- decodedEitherHeader
      publicKey = cachedProvider.get(header.kid).getPublicKey.asInstanceOf[RSAPublicKey]
      alg       = Algorithm.RSA256(TokenVerifier.createPublicKeyProvider(publicKey))
      oidcUser  <- TokenVerifier.validateIdToken(alg, authConfig.authDomain, authConfig.clientId, tokenResponse.idToken)
    } yield {
      oidcUser
    }

    eitherUser.fold(
      errorMessage => InternalServerError(errorMessage),
      user => Directive.success(user)
    )
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
  def storeState(stateRef: String, state: String, returnToUrl: URI, callbackUrl: URI): Unit
  def getState(stateRef: String): Option[State]
  def removeState(stateRef: String): Unit
  def storeSession(key: String, content: OidcAuthenticatedUser): Unit
  def getSession(key: String): Option[OidcAuthenticatedUser]
  def removeSession(key: String): Unit
}

case class State(
    state: String,
    returnToUrl: URI,
    callbackUrl: URI
)
