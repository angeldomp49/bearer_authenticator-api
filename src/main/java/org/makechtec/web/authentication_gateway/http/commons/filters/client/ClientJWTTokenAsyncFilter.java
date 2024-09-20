package org.makechtec.web.authentication_gateway.http.commons.filters.client;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.http.commons.filters.CommonFilterResult;
import org.springframework.http.HttpStatus;

import java.sql.SQLException;

import static org.makechtec.web.authentication_gateway.http.commons.filters.CommonFilterResult.*;

public class ClientJWTTokenAsyncFilter implements RequestValidationAsyncFilter {

    private final BearerAuthenticationFactory bearerAuthenticationFactory;
    private final CommonResponseBuilder commonResponseBuilder;
    private CommonFilterResult result;

    public ClientJWTTokenAsyncFilter(BearerAuthenticationFactory bearerAuthenticationFactory, CommonResponseBuilder commonResponseBuilder) {
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
        this.commonResponseBuilder = commonResponseBuilder;
    }

    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {

            var isValidSignature =
                    bearerAuthenticationFactory.jwtTokenHandler()
                            .isValidSignature((String) context.getItem("clientJWTToken"));

            var isInBlackList =
                    bearerAuthenticationFactory.jwtTokenHandler()
                            .isInBlackList((String) context.getItem("clientJWTToken"));

            var validationResult = isValidSignature && !isInBlackList;

            if (!validationResult) {
                result = UNAUTHORIZED;
                return false;
            }

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
                "Invalid token for this client",
                HttpStatus.UNAUTHORIZED,
                ClientRateLimitAsyncFilter.class
        );
    }

}
