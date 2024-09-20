package org.makechtec.web.authentication_gateway.http.commons.filters.client;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.http.commons.filters.CommonFilterResult;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;

import static org.makechtec.web.authentication_gateway.http.commons.filters.CommonFilterResult.*;

public class ClientCredentialsAsyncFilter implements RequestValidationAsyncFilter {

    private final BearerAuthenticationFactory bearerAuthenticationFactory;
    private final CommonResponseBuilder commonResponseBuilder;
    private CommonFilterResult result;

    public ClientCredentialsAsyncFilter(BearerAuthenticationFactory bearerAuthenticationFactory, CommonResponseBuilder commonResponseBuilder) {
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
        this.commonResponseBuilder = commonResponseBuilder;
    }

    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {

            var validationResult =
                    bearerAuthenticationFactory.userAuthenticator().areValidCredentials(
                            (String) context.getItem("clientUsername"),
                            (String) context.getItem("clientPassword")
                    );

            if(!validationResult){
                result = UNAUTHORIZED;
                return false;
            }

            var session = bearerAuthenticationFactory.sessionGenerator().createForUser((String) context.getItem("username"));

            var token = bearerAuthenticationFactory.jwtTokenHandler().createTokenForSession(session);

            context.setItem("clientCredentialsAsyncFilter.jwtToken", token);

            result = SUCCESS;
            return true;
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            result = DATABASE_CONNECTION_ERROR;
            return false;
        }
    }

    @Override
    public ValidationFailedResponse createFailedResponse(EnvironmentContext context) {

        if (result == DATABASE_CONNECTION_ERROR) {
            return commonResponseBuilder.createDatabaseErrorResponse("Error connecting to the database", ClientRateLimitAsyncFilter.class);
        }

        return commonResponseBuilder.createErrorResponse(
                "Username or password are invalid for client",
                HttpStatus.UNAUTHORIZED,
                ClientRateLimitAsyncFilter.class
        );
    }


}
