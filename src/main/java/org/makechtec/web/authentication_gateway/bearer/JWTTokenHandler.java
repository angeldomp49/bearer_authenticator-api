package org.makechtec.web.authentication_gateway.bearer;

import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.bearer.session.SessionInformation;
import org.makechtec.web.authentication_gateway.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.bearer.token.TokenBuilder;

public class JWTTokenHandler {

    public static final String SECRET_KEY = "secretKey";
    private final SignaturePrinter signaturePrinter = new SignaturePrinter();

    public String createTokenForSession(SessionInformation session) {

        return TokenBuilder.builder()
                .header(
                        ObjectLeaftBuilder.builder()
                                .put("alg", "SHA256")
                                .put("typ", "jwt")
                                .build()
                )
                .payload(
                        ObjectLeaftBuilder.builder()
                                .put("exp", session.expirationDate().getTimeInMillis())
                                .put("uid", session.userId())
                                .put("isClosed", session.isClosed())
                                .build()
                )
                .sign(SECRET_KEY)
                .build();
    }

    public boolean isValidSignature(String token) {
        var components = token.split("\\.");

        var message = components[0] + '.' + components[1] + '.' + SECRET_KEY;

        var reformedToken = signaturePrinter.sign(message);

        return reformedToken.equals(token);
    }

}
