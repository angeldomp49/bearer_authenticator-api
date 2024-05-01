package org.makechtec.web.authentication_gateway.csrf;

import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class CSRFTokenGenerator {

    private final int SALT_LENGTH_BYTES = 16;

    private final String secretKey;

    public CSRFTokenGenerator(String secretKey) {
        this.secretKey = secretKey;
    }

    public String generateCSRFToken() {

        var randomGenerator = new SecureRandom();
        var result = new byte[SALT_LENGTH_BYTES];
        randomGenerator.nextBytes(result);

        return
                Hashing.hmacSha512(secretKey.getBytes(StandardCharsets.UTF_8))
                        .hashString(this.formatSaltToString(result), StandardCharsets.UTF_8)
                        .toString();
    }

    private String formatSaltToString(byte[] salt) {
        var hexString = new StringBuilder();
        for (byte b : salt) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

}
