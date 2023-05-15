package org.makechtec.web.auth_api.rest;

public record LoggedResponse(boolean isLoggedIn, String message, String token) {
}
