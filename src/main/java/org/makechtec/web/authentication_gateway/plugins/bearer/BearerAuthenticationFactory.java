package org.makechtec.web.authentication_gateway.plugins.bearer;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.web.authentication_gateway.plugins.bearer.session.SessionGenerator;
import org.makechtec.web.authentication_gateway.plugins.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.plugins.bearer.user.UserAuthenticator;
import org.makechtec.web.authentication_gateway.plugins.bearer.user.UserProvider;
import org.makechtec.web.authentication_gateway.plugins.bearer.password.PasswordHasher;

import java.util.Calendar;

public class BearerAuthenticationFactory {

    private final ConnectionPool connectionPool;
    private final SignaturePrinter signaturePrinter;
    private final PasswordHasher passwordHasher;

    public BearerAuthenticationFactory(ConnectionPool connectionPool, SignaturePrinter signaturePrinter, PasswordHasher passwordHasher) {
        this.connectionPool = connectionPool;
        this.signaturePrinter = signaturePrinter;
        this.passwordHasher = passwordHasher;
    }

    public UserAuthenticator userAuthenticator() {
        return new UserAuthenticator(new UserProvider(connectionPool), passwordHasher);
    }

    public SessionGenerator sessionGenerator() {
        return new SessionGenerator(30, Calendar.DAY_OF_MONTH, connectionPool);
    }

    public JWTTokenHandler jwtTokenHandler() {
        return new JWTTokenHandler(signaturePrinter, connectionPool);
    }

}
