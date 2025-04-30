package org.makechtec.web.authentication_gateway.resources.client.session;

public record ClientAuthenticationModel(
        long id,
        String username,
        byte[] hashedPassword,
        byte[] salt
) {
}
