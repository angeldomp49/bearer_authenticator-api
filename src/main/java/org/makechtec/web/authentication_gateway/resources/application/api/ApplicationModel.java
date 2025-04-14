package org.makechtec.web.authentication_gateway.resources.application.api;

public record ApplicationModel(
        String accessKey,
        byte[] hashedSecret,
        byte[] salt
) {
}
