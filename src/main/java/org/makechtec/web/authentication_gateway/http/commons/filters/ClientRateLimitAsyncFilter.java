package org.makechtec.web.authentication_gateway.http.commons.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;

public class ClientRateLimitAsyncFilter implements RequestValidationAsyncFilter {

    private final RateLimiter rateLimiter;
    private final CommonResponseBuilder commonResponseBuilder;
    private int result;
    private static final int RESULT_SUCCESS = 1;
    private static final int RESULT_FAILED_SQL_CONNECTION = 2;

    public ClientRateLimitAsyncFilter(RateLimiter rateLimiter, CommonResponseBuilder commonResponseBuilder) {
        this.rateLimiter = rateLimiter;
        this.commonResponseBuilder = commonResponseBuilder;
    }


    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {
            var validationResult =
                    !this.rateLimiter.hasAttemptsThisClient(
                            (String) context.getItem("clientAddress"),
                            (String) context.getItem("clientAgent"),
                            (String) context.getItem("clientAddress"),
                            (String) context.getItem("clientRateLimitTitle")
                    );

            result = RESULT_SUCCESS;

            return validationResult;
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            result = RESULT_FAILED_SQL_CONNECTION;
            return false;
        }
    }

    @Override
    public ValidationFailedResponse createFailedResponse(EnvironmentContext context) {
        if (result == RESULT_FAILED_SQL_CONNECTION) {
            var message =
                    ObjectLeaftBuilder.builder()
                            .put("message", "Error connecting to the database")
                            .build();

            return new ValidationFailedResponse(
                    new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR)
            );
        }

        var message =
                ObjectLeaftBuilder.builder()
                        .put("message", "Too many requests")
                        .build();

        return new ValidationFailedResponse(
                new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.TOO_MANY_REQUESTS), HttpStatus.TOO_MANY_REQUESTS)
        );
    }


}
