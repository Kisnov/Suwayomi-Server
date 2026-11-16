package suwayomi.tachidesk.server.user

import io.javalin.http.Context
import io.javalin.http.Header
import io.mockk.every
import io.mockk.mockk
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import suwayomi.tachidesk.graphql.types.AuthMode
import suwayomi.tachidesk.server.JavalinSetup.Attribute
import suwayomi.tachidesk.server.serverConfig
import suwayomi.tachidesk.test.GraphQLTest
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Tests the checks of the configured `authUsername`/`authPassword`: the basic auth header (which
 * `JavalinSetup` stores as [Attribute.TachideskBasic] and [requireUserWithBasicFallback] turns into
 * user 1), the SIMPLE_LOGIN form and the SIMPLE_LOGIN session.
 *
 * Both settings default to "", so blank configured credentials must never be accepted, or an empty
 * `Authorization: Basic Og==` header (or an empty login form) would authenticate as the admin.
 */
class BasicCredentialsTest : GraphQLTest() {
    private lateinit var ctx: Context

    private lateinit var originalAuthMode: AuthMode
    private lateinit var originalUsername: String
    private lateinit var originalPassword: String

    @BeforeEach
    fun setUp() {
        ctx = mockk<Context>(relaxed = true)
        // parse the real Authorization header stubbed below
        every { ctx.basicAuthCredentials() } answers { callOriginal() }
        // what JavalinSetup.beforeMatched stores for requireUserWithBasicFallback
        every { ctx.attribute<Boolean>(Attribute.TachideskBasic.name) } answers { ctx.basicAuthMatchesConfig() }

        originalAuthMode = serverConfig.authMode.value
        originalUsername = serverConfig.authUsername.value
        originalPassword = serverConfig.authPassword.value
    }

    @AfterEach
    fun tearDown() {
        serverConfig.authMode.value = originalAuthMode
        serverConfig.authUsername.value = originalUsername
        serverConfig.authPassword.value = originalPassword
    }

    private fun configure(
        authMode: AuthMode,
        username: String,
        password: String,
    ) {
        serverConfig.authMode.value = authMode
        serverConfig.authUsername.value = username
        serverConfig.authPassword.value = password
    }

    private fun basicAuth(
        username: String,
        password: String,
    ) {
        val encoded = Base64.getEncoder().encodeToString("$username:$password".toByteArray())
        every { ctx.header(Header.AUTHORIZATION) } returns "Basic $encoded"
    }

    @Test
    fun emptyBasicAuthIsRejectedWhenConfiguredCredentialsAreEmpty() {
        // "Og==" is base64 for ":", i.e. an empty username and password
        every { ctx.header(Header.AUTHORIZATION) } returns "Basic Og=="

        for (authMode in listOf(AuthMode.SIMPLE_LOGIN, AuthMode.UI_LOGIN, AuthMode.BASIC_AUTH)) {
            configure(authMode, "", "")

            assertFalse(ctx.basicAuthMatchesConfig(), "$authMode")
        }
    }

    @Test
    fun emptyBasicAuthDoesNotFallBackToAdminWhenConfiguredCredentialsAreEmpty() {
        every { ctx.header(Header.AUTHORIZATION) } returns "Basic Og=="

        for (authMode in listOf(AuthMode.SIMPLE_LOGIN, AuthMode.UI_LOGIN)) {
            configure(authMode, "", "")

            assertFailsWith<UnauthorizedException>("$authMode") {
                UserType.Visitor.requireUserWithBasicFallback(ctx)
            }
        }
    }

    @Test
    fun blankBasicAuthIsRejectedWhenConfiguredCredentialsAreBlank() {
        configure(AuthMode.UI_LOGIN, " ", " ")
        basicAuth(" ", " ")

        assertFalse(ctx.basicAuthMatchesConfig())
    }

    @Test
    fun basicAuthIsRejectedWhenOnlyTheConfiguredPasswordIsEmpty() {
        configure(AuthMode.UI_LOGIN, "admin", "")
        basicAuth("admin", "")

        assertFalse(ctx.basicAuthMatchesConfig())
        assertFailsWith<UnauthorizedException> { UserType.Visitor.requireUserWithBasicFallback(ctx) }
    }

    @Test
    fun basicAuthIsRejectedWhenOnlyTheConfiguredUsernameIsEmpty() {
        configure(AuthMode.UI_LOGIN, "", "secret")
        basicAuth("", "secret")

        assertFalse(ctx.basicAuthMatchesConfig())
    }

    @Test
    fun matchingBasicAuthFallsBackToAdmin() {
        configure(AuthMode.UI_LOGIN, "admin", "secret")
        basicAuth("admin", "secret")

        assertTrue(ctx.basicAuthMatchesConfig())
        assertEquals(1, UserType.Visitor.requireUserWithBasicFallback(ctx))
    }

    @Test
    fun wrongBasicAuthIsRejected() {
        configure(AuthMode.UI_LOGIN, "admin", "secret")
        basicAuth("admin", "wrong")

        assertFalse(ctx.basicAuthMatchesConfig())
        assertFailsWith<UnauthorizedException> { UserType.Visitor.requireUserWithBasicFallback(ctx) }
    }

    @Test
    fun emptyLoginFormIsRejectedWhenConfiguredCredentialsAreEmpty() {
        configure(AuthMode.SIMPLE_LOGIN, "", "")

        assertFalse(credentialsMatchConfig("", ""))
    }

    @Test
    fun matchingLoginFormIsAccepted() {
        configure(AuthMode.SIMPLE_LOGIN, "admin", "secret")

        assertTrue(credentialsMatchConfig("admin", "secret"))
        assertFalse(credentialsMatchConfig("admin", "wrong"))
        assertFalse(credentialsMatchConfig(null, null))
    }

    @Test
    fun emptyLoggedInSessionIsRejectedWhenConfiguredUsernameIsEmpty() {
        configure(AuthMode.SIMPLE_LOGIN, "", "")

        assertFalse(loggedInUsernameMatchesConfig(""))
    }

    @Test
    fun loggedInSessionIsRejectedWhenConfiguredPasswordIsEmpty() {
        configure(AuthMode.SIMPLE_LOGIN, "admin", "")

        assertFalse(loggedInUsernameMatchesConfig("admin"))
    }

    @Test
    fun matchingLoggedInSessionIsAccepted() {
        configure(AuthMode.SIMPLE_LOGIN, "admin", "secret")

        assertTrue(loggedInUsernameMatchesConfig("admin"))
        assertFalse(loggedInUsernameMatchesConfig("other"))
        assertFalse(loggedInUsernameMatchesConfig(null))
    }
}
