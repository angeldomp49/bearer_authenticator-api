package org.makechtec.web.authentication_gateway.http.commons.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;

public class CSRFTokenAsyncFilter implements RequestValidationAsyncFilter {

    private static final int RESULT_SUCCESS = 1;
    private static final int RESULT_FAILED_SQL_CONNECTION = 2;
    private final CSRFTokenHandler csrfTokenHandler;
    private final CommonResponseBuilder commonResponseBuilder;
    private int result;

    public CSRFTokenAsyncFilter(CSRFTokenHandler csrfTokenHandler, CommonResponseBuilder commonResponseBuilder) {
        this.csrfTokenHandler = csrfTokenHandler;
        this.commonResponseBuilder = commonResponseBuilder;
    }

    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {
            var validationResult =
                    !this.csrfTokenHandler.isValidCSRFToken(
                            (String) context.getItem("userIP"),
                            (String) context.getItem("userAgent"),
                            (String) context.getItem("clientAddress"),
                            (String) context.getItem("csrfToken")
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
                        .put("message", "Unauthorized the CSRF token is invalid")
                        .build();
        return new ValidationFailedResponse(
                new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED)
        );

    }

}
