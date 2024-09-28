package org.makechtec.web.authentication_gateway.plugins.rate_limit.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.commons.filtering.CommonFilterResult;
import org.makechtec.web.authentication_gateway.commons.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.commons.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.plugins.rate_limit.RateLimiter;
import org.springframework.http.HttpStatus;

import java.sql.SQLException;

public class ExternalUserRateLimitAsyncFilter implements RequestValidationAsyncFilter {

    private static final int RESULT_SUCCESS = 1;
    private static final int RESULT_FAILED_SQL_CONNECTION = 2;
    private final RateLimiter rateLimiter;
    private final CommonResponseBuilder commonResponseBuilder;
    private CommonFilterResult result;

    public ExternalUserRateLimitAsyncFilter(RateLimiter rateLimiter, CommonResponseBuilder commonResponseBuilder) {
        this.rateLimiter = rateLimiter;
        this.commonResponseBuilder = commonResponseBuilder;
    }


    @Override
    public boolean canPassRequest(EnvironmentContext context) {

        try {
            var validationResult =
                    this.rateLimiter.hasAttemptsThisUser(
                            (String) context.getItem("externalUserIP"),
                            (String) context.getItem("externalUserAgent"),
                            (String) context.getItem("externalUserRateLimitTitle")
                    );

            if (!validationResult) {
                result = TOO_MANY_REQUESTS;
                return false;
            }

            this.rateLimiter.pushAttemptToThisUser(
                    (String) context.getItem("externalUserIP"),
                    context.getItem("externalUserAgent").toString()
            );

            result = SUCCESS;

            return validationResult;
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
                ExternalUserRateLimitAsyncFilter.class
        );

    }


}
