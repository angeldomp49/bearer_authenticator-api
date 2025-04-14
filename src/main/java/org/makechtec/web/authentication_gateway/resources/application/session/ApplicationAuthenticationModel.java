package org.makechtec.web.authentication_gateway.resources.application.session;

public record ApplicationAuthenticationModel(
        long id,
        String accessKey,
        byte[] hashedPassword,
        byte[] salt
) {
}
