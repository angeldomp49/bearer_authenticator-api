package org.makechtec.web.authentication_gateway.bearer;

import org.makechtec.web.authentication_gateway.bearer.session.SessionGenerator;
import org.makechtec.web.authentication_gateway.bearer.user.UserAuthenticator;

public class BearerAuthenticationFactory {

    public UserAuthenticator userAuthenticator() {
        return new UserAuthenticator();
    }

    public SessionGenerator sessionGenerator() {
        return new SessionGenerator();
    }

    public JWTTokenHandler jwtTokenHandler() {
        return new JWTTokenHandler();
    }

}
