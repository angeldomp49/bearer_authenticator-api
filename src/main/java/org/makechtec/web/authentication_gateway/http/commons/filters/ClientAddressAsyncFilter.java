package org.makechtec.web.authentication_gateway.http.commons.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;

public class ClientAddressAsyncFilter implements RequestValidationAsyncFilter {

    private final ClientValidator clientValidator;
    private final CommonResponseBuilder responseBuilder;

    private int result;
    private static final int RESULT_SUCCESS = 1;
    private static final int RESULT_FAILED_SQL_CONNECTION = 2;

    public ClientAddressAsyncFilter(ClientValidator clientValidator, CommonResponseBuilder responseBuilder) {
        this.clientValidator = clientValidator;
        this.responseBuilder = responseBuilder;
    }


    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        try {
            var validationResult = this.clientValidator.isAllowedClient((String) context.getItem("clientAddress"));
            result = RESULT_SUCCESS;

            return validationResult;
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
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
                    new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR)
            );
        }

        var message =
                ObjectLeaftBuilder.builder()
                        .put("message", "Unauthorized this client is not allowed to do requests")
                        .build();
        return new ValidationFailedResponse(
                new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED)
        );

    }


}
