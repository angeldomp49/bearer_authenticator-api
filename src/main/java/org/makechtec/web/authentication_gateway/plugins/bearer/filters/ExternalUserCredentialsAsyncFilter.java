package org.makechtec.web.authentication_gateway.plugins.bearer.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.commons.filtering.CommonFilterResult;
import org.makechtec.web.authentication_gateway.commons.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.commons.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.plugins.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.plugins.rate_limit.filters.ClientRateLimitAsyncFilter;
import org.springframework.http.HttpStatus;

import java.sql.SQLException;

public class ExternalUserCredentialsAsyncFilter implements RequestValidationAsyncFilter {

    private final BearerAuthenticationFactory bearerAuthenticationFactory;
    private final CommonResponseBuilder commonResponseBuilder;
    private CommonFilterResult result;

    public ExternalUserCredentialsAsyncFilter(BearerAuthenticationFactory bearerAuthenticationFactory, CommonResponseBuilder commonResponseBuilder) {
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
        this.commonResponseBuilder = commonResponseBuilder;
    }

    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {

            var validationResult =
                    bearerAuthenticationFactory.userAuthenticator().areValidCredentials(
                            (String) context.getItem("username"),
                            (String) context.getItem("password")
                    );

            if (!validationResult) {
                result = UNAUTHORIZED;
                return false;
            }

            var session = bearerAuthenticationFactory.sessionGenerator().createForUser((String) context.getItem("username"));

            var token = bearerAuthenticationFactory.jwtTokenHandler().createTokenForSession(session);

            context.setItem("externalUserCredentialsAsyncFilter.jwtToken", token);

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
