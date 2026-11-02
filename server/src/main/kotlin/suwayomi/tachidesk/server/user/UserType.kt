package suwayomi.tachidesk.server.user

import io.javalin.http.Context
import io.javalin.http.Header
import io.javalin.websocket.WsConnectContext
import suwayomi.tachidesk.global.impl.util.Jwt
import suwayomi.tachidesk.graphql.types.AuthMode
import suwayomi.tachidesk.server.JavalinSetup.Attribute
import suwayomi.tachidesk.server.JavalinSetup.getAttribute
import suwayomi.tachidesk.server.serverConfig

sealed class UserType {
    class Admin(
        val id: Int,
        val roles: List<UserRole> = listOf(UserRole.ADMIN),
    ) : UserType()

    class User(
        val id: Int,
        val permissions: List<UserPermission>,
        val roles: List<UserRole> = listOf(UserRole.USER),
    ) : UserType()

    data object Visitor : UserType()
}

fun UserType.requireUser(): Int =
    when (this) {
        is UserType.Admin -> id
        is UserType.User -> id
        UserType.Visitor -> throw UnauthorizedException()
    }

fun UserType.requireUserWithBasicFallback(ctx: Context): Int =
    when (this) {
        is UserType.Admin -> {
            id
        }

        UserType.Visitor if ctx.getAttribute(Attribute.TachideskBasic) -> {
            1
        }

        UserType.Visitor -> {
            ctx.header("WWW-Authenticate", "Basic")
            throw UnauthorizedException()
        }

        is UserType.User -> {
            id
        }
    }

/**
 * Whether [username]/[password] match the configured `authUsername`/`authPassword`.
 *
 * Both settings default to "", so blank configured credentials never match. Otherwise an empty
 * `Authorization: Basic Og==` header or an empty login form would authenticate as the admin.
 */
fun credentialsMatchConfig(
    username: String?,
    password: String?,
): Boolean {
    val configuredUsername = serverConfig.authUsername.value
    val configuredPassword = serverConfig.authPassword.value
    if (configuredUsername.isBlank() || configuredPassword.isBlank()) {
        return false
    }
    return username == configuredUsername && password == configuredPassword
}

/**
 * Whether the request's basic auth credentials match the configured `authUsername`/`authPassword`.
 */
fun Context.basicAuthMatchesConfig(): Boolean {
    val (username, password) = basicAuthCredentials() ?: return false
    return credentialsMatchConfig(username, password)
}

/**
 * Whether the `logged-in` session attribute (set by the SIMPLE_LOGIN form) names the configured `authUsername`.
 *
 * Like [credentialsMatchConfig], nothing matches while either configured value is blank, so clearing
 * `authPassword` also ends existing sessions.
 */
fun loggedInUsernameMatchesConfig(username: String?): Boolean {
    val configuredUsername = serverConfig.authUsername.value
    if (configuredUsername.isBlank() || serverConfig.authPassword.value.isBlank()) {
        return false
    }
    return username == configuredUsername
}

suspend fun getUserFromToken(token: String?): UserType {
    if (serverConfig.authMode.value != AuthMode.UI_LOGIN) {
        return UserType.Admin(1)
    }

    if (token.isNullOrBlank()) {
        return UserType.Visitor
    }

    return Jwt.verifyJwt(token)
}

fun UserType.requirePermissions(vararg permissions: UserPermission) {
    when (this) {
        is UserType.Admin -> {}

        is UserType.User -> {
            val userPermissions = this.permissions
            if (!permissions.all { it in userPermissions }) {
                throw ForbiddenException()
            }
        }

        UserType.Visitor -> {
            throw UnauthorizedException()
        }
    }
}

suspend fun getUserFromContext(ctx: Context): UserType {
    fun cookieValid(): Boolean = loggedInUsernameMatchesConfig(ctx.sessionAttribute<String>("logged-in"))

    return when (serverConfig.authMode.value) {
        // NOTE: Basic Auth is expected to have been validated by JavalinSetup
        AuthMode.NONE, AuthMode.BASIC_AUTH -> {
            UserType.Admin(1)
        }

        AuthMode.SIMPLE_LOGIN -> {
            if (cookieValid()) UserType.Admin(1) else UserType.Visitor
        }

        AuthMode.UI_LOGIN -> {
            val authentication = ctx.header(Header.AUTHORIZATION) ?: ctx.cookie("suwayomi-server-token")
            val token = authentication?.substringAfter("Bearer ") ?: ctx.queryParam("token")

            getUserFromToken(token)
        }
    }
}

suspend fun getUserFromWsContext(ctx: WsConnectContext): UserType {
    fun cookieValid(): Boolean = loggedInUsernameMatchesConfig(ctx.sessionAttribute<String>("logged-in"))

    return when (serverConfig.authMode.value) {
        // NOTE: Basic Auth is expected to have been validated by JavalinSetup
        AuthMode.NONE, AuthMode.BASIC_AUTH -> {
            UserType.Admin(1)
        }

        AuthMode.SIMPLE_LOGIN -> {
            if (cookieValid()) UserType.Admin(1) else UserType.Visitor
        }

        AuthMode.UI_LOGIN -> {
            val authentication =
                ctx.header(Header.AUTHORIZATION) ?: ctx.cookie("suwayomi-server-token")
            val token = authentication?.substringAfter("Bearer ") ?: ctx.queryParam("token")

            getUserFromToken(token)
        }
    }
}

class UnauthorizedException : IllegalStateException("Unauthorized")

class ForbiddenException : IllegalStateException("Forbidden")
