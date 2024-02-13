package org.makechtec.web.authentication_gateway.bearer.token;

import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;

public class SignaturePrinter {

    public String sign(String message) {
        return
                Hashing.sha256()
                        .hashString(message, StandardCharsets.UTF_8)
                        .toString();
    }

}
