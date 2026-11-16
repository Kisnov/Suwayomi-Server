package suwayomi.tachidesk.server.user

/*
 * Copyright (C) Contributors to the Suwayomi project
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

import io.github.reactivecircus.cache4k.Cache
import org.jetbrains.exposed.v1.core.eq
import org.jetbrains.exposed.v1.core.lowerCase
import org.jetbrains.exposed.v1.jdbc.selectAll
import org.jetbrains.exposed.v1.jdbc.transactions.transaction
import suwayomi.tachidesk.global.impl.util.Bcrypt
import suwayomi.tachidesk.global.model.table.UserAccountTable
import suwayomi.tachidesk.global.model.table.UserPermissionsTable
import suwayomi.tachidesk.global.model.table.UserRolesTable
import java.security.MessageDigest
import kotlin.time.Duration.Companion.minutes

/**
 * Checks the username and password of user accounts.
 */
object UserCredentials {
    private class VerifiedLogin(
        val userId: Int,
        val passwordHash: String,
    )

    // Bcrypt is deliberately slow, while clients sending Basic credentials repeat them with every request
    private val verifiedLogins =
        Cache
            .Builder<String, VerifiedLogin>()
            .expireAfterWrite(10.minutes)
            .maximumCacheSize(64)
            .build()

    /**
     * @return the id of the account [username] and [password] belong to, or `null` if they don't match an account
     */
    fun verify(
        username: String,
        password: String,
    ): Int? {
        val account =
            transaction {
                UserAccountTable
                    .selectAll()
                    .where { UserAccountTable.username.lowerCase() eq username.lowercase() }
                    .firstOrNull()
            } ?: return null
        val userId = account[UserAccountTable.id].value
        val passwordHash = account[UserAccountTable.password]

        // A password change stores a new hash, so a login verified against the previous password is not reused
        val cacheKey = cacheKey(username, password)
        val cached = verifiedLogins.get(cacheKey)
        if (cached != null && cached.userId == userId && cached.passwordHash == passwordHash) {
            return userId
        }

        if (!Bcrypt.verify(passwordHash, password)) {
            return null
        }
        verifiedLogins.put(cacheKey, VerifiedLogin(userId, passwordHash))
        return userId
    }

    /**
     * Loads the account [userId] with its roles and permissions, the same way an access token resolves it.
     */
    fun loadUser(userId: Int): UserType {
        val (roleNames, permissionNames) =
            transaction {
                val roles =
                    UserRolesTable
                        .selectAll()
                        .where { UserRolesTable.user eq userId }
                        .map { it[UserRolesTable.role] }
                val permissions =
                    UserPermissionsTable
                        .selectAll()
                        .where { UserPermissionsTable.user eq userId }
                        .map { it[UserPermissionsTable.permission] }
                roles to permissions
            }

        val roles = roleNames.mapNotNull { role -> UserRole.entries.find { it.name == role } }
        val permissions = permissionNames.mapNotNull { permission -> UserPermission.entries.find { it.name == permission } }

        return if (UserRole.ADMIN in roles) {
            UserType.Admin(userId, roles)
        } else {
            UserType.User(id = userId, permissions = permissions, roles = roles)
        }
    }

    // only a digest of the password is kept in memory
    private fun cacheKey(
        username: String,
        password: String,
    ): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(username.lowercase().toByteArray())
        digest.update(0.toByte())
        digest.update(password.toByteArray())
        return digest.digest().toHexString()
    }
}
