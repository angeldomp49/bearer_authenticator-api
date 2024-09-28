package org.makechtec.web.authentication_gateway.plugins.csrf.actions;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.commons.asyn_http.FailedAsyncActionResponse;
import org.makechtec.web.authentication_gateway.commons.asyn_http.HttpAsyncAction;
import org.makechtec.web.authentication_gateway.plugins.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.plugins.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;
import java.util.Calendar;

public class GenerateCSRFTokenAction implements HttpAsyncAction {


    private static final int RESULT_SUCCESS = 1;
    private static final int RESULT_SQL_CONNECTION_ERROR = 2;

    private final CSRFTokenGenerator csrfTokenGenerator;
    private final CSRFTokenHandler csrfTokenHandler;
    private final CommonResponseBuilder commonResponseBuilder;

    private int result;

    public GenerateCSRFTokenAction(CSRFTokenGenerator csrfTokenGenerator, CSRFTokenHandler csrfTokenHandler, CommonResponseBuilder commonResponseBuilder) {
        this.csrfTokenGenerator = csrfTokenGenerator;
        this.csrfTokenHandler = csrfTokenHandler;
        this.commonResponseBuilder = commonResponseBuilder;
    }

    @Override
    public void perform(EnvironmentContext context) {

        Calendar expirationDate = Calendar.getInstance();
        expirationDate.add(Calendar.MINUTE, 30);

        var csrfToken = this.csrfTokenGenerator.generateCSRFToken();

        try {
            this.csrfTokenHandler.registerCSRFToken(
                    (String) context.getItem("userIP"),
                    (String) context.getItem("userAgent"),
                    expirationDate.getTimeInMillis(),
                    csrfToken
            );

        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            result = RESULT_SQL_CONNECTION_ERROR;
            return;
        }

        context.setItem("csrfToken", csrfToken);

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
