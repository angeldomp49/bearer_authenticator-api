package org.makechtec.web.authentication_gateway.plugins.csrf.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.commons.filtering.CommonFilterResult;
import org.makechtec.web.authentication_gateway.commons.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.commons.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.plugins.csrf.ClientValidator;
import org.springframework.http.HttpStatus;

import java.sql.SQLException;

public class ClientWhiteListAsyncFilter implements RequestValidationAsyncFilter {

    private final ClientValidator clientValidator;
    private final CommonResponseBuilder responseBuilder;
    private CommonFilterResult result;

    public ClientWhiteListAsyncFilter(ClientValidator clientValidator, CommonResponseBuilder responseBuilder) {
        this.clientValidator = clientValidator;
        this.responseBuilder = responseBuilder;
    }


    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {
            var validationResult = this.clientValidator.isAllowedClient((String) context.getItem("clientIP"));

            if (!validationResult) {
                result = UNAUTHORIZED;
                return false;
            }

            result = SUCCESS;
            return validationResult;
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            result = DATABASE_CONNECTION_ERROR;
            return false;
        }
    }

    @Override
    public ValidationFailedResponse createFailedResponse(EnvironmentContext context) {
        if (result == DATABASE_CONNECTION_ERROR) {
            return responseBuilder.createDatabaseErrorResponse("Error connecting to the database", ClientWhiteListAsyncFilter.class);
        }

        return responseBuilder.createErrorResponse(
                "Unauthorized this client is not allowed",
                HttpStatus.UNAUTHORIZED,
                ClientWhiteListAsyncFilter.class
        );

    }


}
