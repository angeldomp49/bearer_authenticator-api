package org.makechtec.web.authentication_gateway.http.commons.actions;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.asyn_http.FailedAsyncActionResponse;
import org.makechtec.web.authentication_gateway.asyn_http.HttpAsyncAction;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;

public class PushUserAttemptAction implements HttpAsyncAction {

    private static final int RESULT_SUCCESS = 1;
    private static final int RESULT_SQL_CONNECTION_ERROR = 2;

    private final RateLimiter rateLimiter;
    private final CommonResponseBuilder commonResponseBuilder;

    private int result;

    public PushUserAttemptAction(RateLimiter rateLimiter, CommonResponseBuilder commonResponseBuilder) {
        this.rateLimiter = rateLimiter;
        this.commonResponseBuilder = commonResponseBuilder;
    }


    @Override
    public void perform(EnvironmentContext context) {


        try {
            this.rateLimiter.pushAttemptToThisClient(
                    (String) context.getItem("userIP"),
                    context.getItem("userAgent").toString(),
                    ""
            );

            result = RESULT_SUCCESS;
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            result = RESULT_SQL_CONNECTION_ERROR;
        }



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
