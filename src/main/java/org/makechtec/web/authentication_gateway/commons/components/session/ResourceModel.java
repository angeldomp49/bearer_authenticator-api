package org.makechtec.web.authentication_gateway.commons.components.session;

record ResourceModel(
        long id,
        String kind,
        String accessKey,
        byte[] hashedSecret,
        byte[] salt,
        String specificAttributes
) {
}
