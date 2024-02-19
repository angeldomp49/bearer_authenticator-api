package org.makechtec.web.authentication_gateway.bearer.user;

public record User(String username, String hashedPassword, long id) {
}
