package org.makechtec.web.authentication_gateway.http.rest;

public record LoggedResponse(boolean isLoggedIn, String message, String token) {
}
