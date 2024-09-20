package org.makechtec.web.authentication_gateway.http.commons.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.filtering.ValidationFailedResponse;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;

public class UserCredentialsAsyncFilter implements RequestValidationAsyncFilter {

    private static final int RESULT_SUCCESS = 1;
    private static final int RESULT_FAILED_SQL_CONNECTION = 2;
    private final BearerAuthenticationFactory bearerAuthenticationFactory;
    private final CommonResponseBuilder commonResponseBuilder;
    private int result;

    public UserCredentialsAsyncFilter(BearerAuthenticationFactory bearerAuthenticationFactory, CommonResponseBuilder commonResponseBuilder) {
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
                    new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR),
                    UserCredentialsAsyncFilter.class.getName()
            );
        }

        var message =
                ObjectLeaftBuilder.builder()
                        .put("message", "Username or password are invalid")
                        .build();

        return new ValidationFailedResponse(
                new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED),
                UserCredentialsAsyncFilter.class.getName()
        );
    }


}
