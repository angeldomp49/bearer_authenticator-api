package org.makechtec.web.authentication_gateway.plugins.admin.api.user;

public record StoredUserModel(String username, String email, String hashedPassword, byte[] salt) {
}
