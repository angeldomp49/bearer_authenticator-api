package org.makechtec.web.authentication_gateway.password;

import java.security.SecureRandom;

public class SaltGenerator {

    private final int SALT_LENGTH_BYTES = 16;

    public byte[] generate(){
        var randomGenerator = new SecureRandom();
        var result = new byte[SALT_LENGTH_BYTES];
        randomGenerator.nextBytes(result);
        return result;
    }

    public String formatSaltToString(byte[] salt){
        var hexString = new StringBuilder();
        for (byte b : salt) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

}
