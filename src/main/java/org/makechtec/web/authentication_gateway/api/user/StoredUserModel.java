package org.makechtec.web.authentication_gateway.api.user;

public record StoredUserModel(String username, String email, String hashedPassword, byte[] salt) {
}
