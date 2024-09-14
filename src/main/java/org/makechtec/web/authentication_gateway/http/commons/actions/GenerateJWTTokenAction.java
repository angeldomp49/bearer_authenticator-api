package org.makechtec.web.authentication_gateway.http.commons.actions;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.asyn_http.FailedAsyncActionResponse;
import org.makechtec.web.authentication_gateway.asyn_http.HttpAsyncAction;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.bearer.session.SessionInformation;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;

public class GenerateJWTTokenAction implements HttpAsyncAction {

    private static final int RESULT_SUCCESS = 1;
    private static final int RESULT_SQL_CONNECTION_ERROR = 2;

    private final BearerAuthenticationFactory bearerAuthenticationFactory;
    private final CommonResponseBuilder commonResponseBuilder;

    private int result;

    public GenerateJWTTokenAction(BearerAuthenticationFactory bearerAuthenticationFactory, CommonResponseBuilder commonResponseBuilder) {
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
        this.commonResponseBuilder = commonResponseBuilder;
    }

    @Override
    public void perform(EnvironmentContext context) {
        SessionInformation session;

        try {
            session = bearerAuthenticationFactory.sessionGenerator().createForUser((String) context.getItem("username"));
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            result = RESULT_SQL_CONNECTION_ERROR;
            return;
        }

        var token = bearerAuthenticationFactory.jwtTokenHandler().createTokenForSession(session);

        context.setItem("jwtToken", token);

        result = RESULT_SUCCESS;
    }

    @Override
    public boolean hasSuccessfulFinished(EnvironmentContext context) {
        return result == RESULT_SUCCESS;
    }

    @Override
    public FailedAsyncActionResponse createFailedResponse(EnvironmentContext context) {
        var message =
                ObjectLeaftBuilder.builder()
                        .put("message", "There was an error in the connection to the database")
                        .build();

        return new FailedAsyncActionResponse(
                new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR)
        );
    }

}
