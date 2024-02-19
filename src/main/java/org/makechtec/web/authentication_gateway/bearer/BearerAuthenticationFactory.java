package org.makechtec.web.authentication_gateway.bearer;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.web.authentication_gateway.bearer.session.SessionGenerator;
import org.makechtec.web.authentication_gateway.bearer.user.UserAuthenticator;
import org.makechtec.web.authentication_gateway.bearer.user.UserProvider;

import java.util.Calendar;

public class BearerAuthenticationFactory {

    private final ConnectionInformation connectionInformation;

    public BearerAuthenticationFactory(ConnectionInformation connectionInformation) {
        this.connectionInformation = connectionInformation;
    }

    public UserAuthenticator userAuthenticator() {
        return new UserAuthenticator(new UserProvider(connectionInformation));
    }

    public SessionGenerator sessionGenerator() {
        return new SessionGenerator(30, Calendar.DAY_OF_MONTH, connectionInformation);
    }

    public JWTTokenHandler jwtTokenHandler() {
        return new JWTTokenHandler();
    }

}
