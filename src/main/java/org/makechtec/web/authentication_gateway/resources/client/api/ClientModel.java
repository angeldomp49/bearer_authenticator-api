package org.makechtec.web.authentication_gateway.resources.client.api;

public record ClientModel(
        String username,
        String email,
        String hashedPassword,
        byte[] salt
) {
}
