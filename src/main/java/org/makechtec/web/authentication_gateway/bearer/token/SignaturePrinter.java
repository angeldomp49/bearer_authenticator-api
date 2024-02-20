package org.makechtec.web.authentication_gateway.bearer.token;

import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;

public class SignaturePrinter {

    private final String secretKey;

    public SignaturePrinter(String secretKey) {
        this.secretKey = secretKey;
    }

    public String sign(String message) {
        return
                Hashing.hmacSha512(secretKey.getBytes(StandardCharsets.UTF_8))
                        .hashString(message, StandardCharsets.UTF_8)
                        .toString();
    }

}
