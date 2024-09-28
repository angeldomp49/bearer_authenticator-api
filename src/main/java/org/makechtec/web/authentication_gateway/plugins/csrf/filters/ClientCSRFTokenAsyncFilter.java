package org.makechtec.web.authentication_gateway.plugins.csrf.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.commons.filtering.CommonFilterResult;
import org.makechtec.web.authentication_gateway.commons.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.commons.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.plugins.csrf.CSRFTokenHandler;
import org.springframework.http.HttpStatus;

import java.sql.SQLException;

import static org.makechtec.web.authentication_gateway.commons.filtering.CommonFilterResult.DATABASE_CONNECTION_ERROR;
import static org.makechtec.web.authentication_gateway.commons.filtering.CommonFilterResult.SUCCESS;

public class ClientCSRFTokenAsyncFilter implements RequestValidationAsyncFilter {


    private final CSRFTokenHandler csrfTokenHandler;
    private final CommonResponseBuilder commonResponseBuilder;
    private CommonFilterResult result;

    public ClientCSRFTokenAsyncFilter(CSRFTokenHandler csrfTokenHandler, CommonResponseBuilder commonResponseBuilder) {
        this.csrfTokenHandler = csrfTokenHandler;
        this.commonResponseBuilder = commonResponseBuilder;
    }

    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {
            var clientCSRFToken = (String) context.getItem("clientCSRFToken");

            var validationResult =
                    this.csrfTokenHandler.isValidCSRFToken(
                            (String) context.getItem("clientIP"),
                            (String) context.getItem("clientAgent"),
                            clientCSRFToken
                    );

            csrfTokenHandler.deleteCSRFToken(clientCSRFToken);

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
            return commonResponseBuilder.createDatabaseErrorResponse("Error connecting to the database", ClientCSRFTokenAsyncFilter.class);
        }

        return commonResponseBuilder.createErrorResponse(
                "Unauthorized the CSRF token is invalid",
                HttpStatus.UNAUTHORIZED,
                ClientCSRFTokenAsyncFilter.class
        );

    }


}
