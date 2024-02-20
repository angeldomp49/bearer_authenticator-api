package org.makechtec.web.authentication_gateway.bearer;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.web.authentication_gateway.bearer.session.SessionGenerator;
import org.makechtec.web.authentication_gateway.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.bearer.user.UserAuthenticator;
import org.makechtec.web.authentication_gateway.bearer.user.UserProvider;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;

import java.util.Calendar;

public class BearerAuthenticationFactory {

    private final ConnectionInformation connectionInformation;
    private final SignaturePrinter signaturePrinter;
    private final PasswordHasher passwordHasher;

    public BearerAuthenticationFactory(ConnectionInformation connectionInformation, SignaturePrinter signaturePrinter, PasswordHasher passwordHasher) {
        this.connectionInformation = connectionInformation;
        this.signaturePrinter = signaturePrinter;
        this.passwordHasher = passwordHasher;
    }

    public UserAuthenticator userAuthenticator() {
        return new UserAuthenticator(new UserProvider(connectionInformation), passwordHasher);
    }

    public SessionGenerator sessionGenerator() {
        return new SessionGenerator(30, Calendar.DAY_OF_MONTH, connectionInformation);
    }

    public JWTTokenHandler jwtTokenHandler() {
        return new JWTTokenHandler(connectionInformation, signaturePrinter);
    }

}
