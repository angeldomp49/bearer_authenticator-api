package org.makechtec.web.authentication_gateway.plugins.rate_limit.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.commons.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.commons.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.filtering.CommonFilterResult;
import org.makechtec.web.authentication_gateway.plugins.rate_limit.RateLimiter;
import org.springframework.http.HttpStatus;

import java.sql.SQLException;

public class ClientRateLimitAsyncFilter implements RequestValidationAsyncFilter {

    private final RateLimiter rateLimiter;
    private final CommonResponseBuilder commonResponseBuilder;
    private CommonFilterResult result;

    public ClientRateLimitAsyncFilter(RateLimiter rateLimiter, CommonResponseBuilder commonResponseBuilder) {
        this.rateLimiter = rateLimiter;
        this.commonResponseBuilder = commonResponseBuilder;
    }


    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {
            var validationResult =
                    this.rateLimiter.hasAttemptsThisUser(
                            (String) context.getItem("clientIP"),
                            (String) context.getItem("clientAgent"),
                            (String) context.getItem("clientRateLimitTitle")
                    );

            if (!validationResult) {
                result = TOO_MANY_REQUESTS;
                return false;
            }

            this.rateLimiter.pushAttemptToThisUser(
                    (String) context.getItem("clientIP"),
                    context.getItem("clientAgent").toString()
            );

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
                "Too many requests",
                HttpStatus.TOO_MANY_REQUESTS,
                ClientRateLimitAsyncFilter.class
        );

    }


}
