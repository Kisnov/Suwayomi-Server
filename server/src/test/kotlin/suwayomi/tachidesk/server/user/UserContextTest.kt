package suwayomi.tachidesk.server.user

import io.javalin.http.Context
import io.javalin.http.Header
import io.javalin.security.BasicAuthCredentials
import io.javalin.websocket.WsConnectContext
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import suwayomi.tachidesk.global.impl.util.Jwt
import suwayomi.tachidesk.graphql.types.AuthMode
import suwayomi.tachidesk.server.serverConfig
import suwayomi.tachidesk.test.GraphQLTest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull

/**
 * Tests the HTTP-level authentication seam: [getUserFromContext] parsing the bearer token (or
 * its cookie / query-param fallbacks) from a Javalin [Context] and resolving it to a [UserType].
 *
 * This is where a stale or invalid token actually meets a GraphQL request.
 */
class UserContextTest : GraphQLTest() {
    // A fresh mock per test: the class runs PER_CLASS, so a shared mock would leak
    // `every { }` stubs (e.g. a bearer header) between test methods.
    private lateinit var ctx: Context

    // Initialized in @BeforeEach, not in a property initializer: with PER_CLASS the
    // constructor runs before @BeforeAll has set up the app, so serverConfig is not yet
    // available at construction time.
    private lateinit var originalAuthMode: AuthMode
    private lateinit var originalAuthUsername: String
    private lateinit var originalAuthPassword: String

    @BeforeEach
    fun setUp() {
        ctx = mockk<Context>(relaxed = true)
        originalAuthMode = serverConfig.authMode.value
        originalAuthUsername = serverConfig.authUsername.value
        originalAuthPassword = serverConfig.authPassword.value
        serverConfig.authMode.value = AuthMode.UI_LOGIN
    }

    @AfterEach
    fun tearDown() {
        serverConfig.authMode.value = originalAuthMode
        serverConfig.authUsername.value = originalAuthUsername
        serverConfig.authPassword.value = originalAuthPassword
    }

    private fun basic(
        ctx: Context,
        username: String,
        password: String,
    ) {
        val encoded = Base64.getEncoder().encodeToString("$username:$password".toByteArray())
        every { ctx.header(Header.AUTHORIZATION) } returns "Basic $encoded"
        every { ctx.basicAuthCredentials() } returns BasicAuthCredentials(username, password)
    }

    private fun bearer(
        ctx: Context,
        token: String,
    ) {
        every { ctx.header(Header.AUTHORIZATION) } returns "Bearer $token"
    }

    // Javalin's Context.header(name) is a platform type, so a relaxed mock returns "" (not
    // null); explicitly stub it to null so the cookie / query-param fallbacks are reached.
    private fun noAuthHeader(ctx: Context) {
        every { ctx.header(Header.AUTHORIZATION) } returns null
    }

    @Test
    fun bearerAccessTokenResolvesToUser() =
        runTest {
            val userId = createTestUser("jwtuser")
            val tokens = Jwt.generateJwt(userId)

            val user = getUserFromContext(ctx.also { bearer(it, tokens.accessToken) })

            assertIs<UserType.User>(user)
            assertEquals(userId, user.id)
        }

    @Test
    fun bearerAccessTokenForAdminResolvesToAdmin() =
        runTest {
            val tokens = Jwt.generateJwt(1)

            val user = getUserFromContext(ctx.also { bearer(it, tokens.accessToken) })

            assertIs<UserType.Admin>(user)
            assertEquals(1, user.id)
        }

    @Test
    fun cookieTokenFallsBackWhenNoAuthorizationHeader() =
        runTest {
            val userId = createTestUser("jwtcookieuser")
            val tokens = Jwt.generateJwt(userId)

            noAuthHeader(ctx)
            every { ctx.cookie("suwayomi-server-token") } returns tokens.accessToken

            val user = getUserFromContext(ctx)

            assertIs<UserType.User>(user)
            assertEquals(userId, user.id)
        }

    @Test
    fun queryParamTokenFallsBackWhenNoHeaderOrCookie() =
        runTest {
            val userId = createTestUser("jwtqueryuser")
            val tokens = Jwt.generateJwt(userId)

            noAuthHeader(ctx)
            every { ctx.cookie("suwayomi-server-token") } returns null
            every { ctx.queryParam("token") } returns tokens.accessToken

            val user = getUserFromContext(ctx)

            assertIs<UserType.User>(user)
            assertEquals(userId, user.id)
        }

    @Test
    fun missingTokenResolvesToVisitor() =
        runTest {
            val user = getUserFromContext(ctx)

            assertIs<UserType.Visitor>(user)
        }

    @Test
    fun staleAccessTokenAfterSessionBumpResolvesToVisitor() =
        runTest {
            val userId = createTestUser("jwtstaleuser")
            val tokens = Jwt.generateJwt(userId)

            // a password change (or recovery redemption) bumps the session version
            SessionVersion.bump(userId)

            val user = getUserFromContext(ctx.also { bearer(it, tokens.accessToken) })

            assertIs<UserType.Visitor>(user)
        }

    @Test
    fun refreshTokenUsedAsAccessTokenResolvesToVisitor() =
        runTest {
            val userId = createTestUser("jwtrefreshuser")
            val tokens = Jwt.generateJwt(userId)

            val user = getUserFromContext(ctx.also { bearer(it, tokens.refreshToken) })

            assertIs<UserType.Visitor>(user)
        }

    @Test
    fun nonUiLoginModeResolvesToAdminWithoutToken() =
        runTest {
            serverConfig.authMode.value = AuthMode.BASIC_AUTH

            val user = getUserFromContext(ctx)

            assertIs<UserType.Admin>(user)
            assertEquals(1, user.id)
        }

    @Test
    fun basicAuthorizationHeaderIsNotTreatedAsToken() =
        runTest {
            val userId = createTestUser("jwtbasiccookieuser")
            val tokens = Jwt.generateJwt(userId)

            basic(ctx, "admin", "secret")
            every { ctx.cookie("suwayomi-server-token") } returns tokens.accessToken

            val user = getUserFromContext(ctx)

            assertIs<UserType.User>(user)
            assertEquals(userId, user.id)
        }

    @Test
    fun basicAuthorizationHeaderIsNotTreatedAsTokenOnWebSocket() =
        runTest {
            val userId = createTestUser("jwtbasicwsuser")
            val tokens = Jwt.generateJwt(userId)

            val wsCtx = mockk<WsConnectContext>(relaxed = true)
            every { wsCtx.header(Header.AUTHORIZATION) } returns "Basic YWRtaW46c2VjcmV0"
            every { wsCtx.cookie("suwayomi-server-token") } returns tokens.accessToken

            val user = getUserFromWsContext(wsCtx)

            assertIs<UserType.User>(user)
            assertEquals(userId, user.id)
        }

    @Test
    fun validBasicCredentialsResolveVisitorToAdmin() {
        serverConfig.authUsername.value = "admin"
        serverConfig.authPassword.value = "secret"
        basic(ctx, "admin", "secret")

        val user = UserType.Visitor.withBasicCredentials(ctx)

        assertIs<UserType.Admin>(user)
        assertEquals(1, user.id)
    }

    @Test
    fun invalidBasicCredentialsAreRejected() {
        serverConfig.authUsername.value = "admin"
        serverConfig.authPassword.value = "secret"
        basic(ctx, "admin", "wrong")

        assertNull(UserType.Visitor.withBasicCredentials(ctx))
    }

    @Test
    fun emptyBasicCredentialsAreRejectedWithoutConfiguredCredentials() {
        serverConfig.authUsername.value = ""
        serverConfig.authPassword.value = ""
        basic(ctx, "", "")

        assertNull(UserType.Visitor.withBasicCredentials(ctx))
    }

    @Test
    fun missingBasicCredentialsKeepVisitor() {
        every { ctx.basicAuthCredentials() } returns null

        assertIs<UserType.Visitor>(UserType.Visitor.withBasicCredentials(ctx))
    }

    @Test
    fun basicCredentialsDoNotReplaceAuthenticatedUser() {
        serverConfig.authUsername.value = "admin"
        serverConfig.authPassword.value = "secret"
        basic(ctx, "admin", "secret")
        val loggedIn = UserType.User(id = 42, permissions = emptyList())

        val user = loggedIn.withBasicCredentials(ctx)

        assertIs<UserType.User>(user)
        assertEquals(42, user.id)
    }
}
