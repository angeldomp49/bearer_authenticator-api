package org.makechtec.web.authentication_gateway.commons.components.random_string;

import java.security.SecureRandom;
import java.util.stream.IntStream;

public class RandomStringGenerator {

    private static final int MAX_LENGTH = 50;
    private static final String CHARACTER_RANGE = "0123456789ABCDEFGHIJKLMNÑOPQRSTUVWXYZabcdefghijklmnñopqrstuvwxyz|!\"#$%&/()='?¿¡+*{}[]´¨-.,_:;«~`^–…@<>≤≥";

    public String generateTemporarySecretKey() {
        var rand = new SecureRandom();
        var length = rand.nextInt(MAX_LENGTH);
        var sb = new StringBuilder();

        IntStream.range(0, length).forEach(i -> sb.append(CHARACTER_RANGE.charAt(rand.nextInt(CHARACTER_RANGE.length()))));

        return sb.toString();

    }

}
