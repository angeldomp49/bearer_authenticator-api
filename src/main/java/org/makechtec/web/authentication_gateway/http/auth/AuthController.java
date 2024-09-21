package org.makechtec.web.authentication_gateway.http.auth;


import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.asyn_http.HttpAsyncActionConfigurer;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationFilterConfigurer;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.ioc.ManuallyInjectable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;

import static org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper.iocContainer;

@RestController
@RequestMapping("/auth")
public class AuthController implements ManuallyInjectable {

    private final HttpServletRequest request;

    private BearerAuthenticationFactory bearerAuthenticationFactory;
    private CommonResponseBuilder commonResponseBuilder;
    private RequestValidationFilterConfigurer requestValidationFilterConfigurer;
    private HttpAsyncActionConfigurer httpAsyncActionConfigurer;

    @Autowired
    public AuthController(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public void inject() {
        this.commonResponseBuilder = (CommonResponseBuilder) iocContainer.getSingleton("commonResponseBuilder");
        this.bearerAuthenticationFactory = (BearerAuthenticationFactory) iocContainer.getSingleton("bearerAuthenticationFactory");
        this.requestValidationFilterConfigurer = (RequestValidationFilterConfigurer) iocContainer.getSingleton("requestValidationFilterConfigurer");
        this.httpAsyncActionConfigurer = (HttpAsyncActionConfigurer) iocContainer.getSingleton("httpAsyncActionConfigurer");
    }

    @PostMapping(
            value = "/client/login",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> loginForClient(
            @RequestHeader("User-Agent") String clientAgent,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,
            @RequestBody String body
    ) {

        var jsonBody = new JSONObject(body);

        var clientAddress = request.getRemoteAddr();
        String username = jsonBody.getString("clientUsername");
        String password = jsonBody.getString("clientPassword");

        var context = new EnvironmentContext();

        context.setItem("clientIP", clientAddress);
        context.setItem("clientAgent", clientAgent);
        context.setItem("clientCSRFToken", xCsrfToken);
        context.setItem("clientUsername", username);
        context.setItem("clientPassword", password);
        context.setItem("csrfToken", xCsrfToken);
        context.setItem("clientRateLimitTitle", "auth.client.login");

        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("authControllerFilters", "client/login")
                        .stream()
                        .filter(validationFilter -> validationFilter.canPassRequest(context))
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
            return possiblyErrorResponse.get().responseEntity();
        }

        var possiblyErrorInAction =
                httpAsyncActionConfigurer.provideActions("authControllerActions", "login")
                        .stream()
                        .parallel()
                        .peek(action -> action.perform(context))
                        .filter(action -> !action.hasSuccessfulFinished(context))
                        .map(action -> action.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorInAction.isPresent()) {
            return possiblyErrorInAction.get().responseEntity();
        }

        var jwtToken = (String) context.getItem("clientCredentialsAsyncFilter.jwtToken");

        var message =
                ObjectLeaftBuilder.builder()
                        .put("token", jwtToken)
                        .build();

        return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

    }

    @GetMapping(value = "/client/check", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> checkForClient(
            @RequestHeader("User-Agent") String clientAgent,
            @RequestHeader("Authorization") String authorization
    ) {
        var token = authorization.replace("Bearer ", "").trim();

        var clientAddress = request.getRemoteAddr();

        var context = new EnvironmentContext();

        context.setItem("clientIP", clientAddress);
        context.setItem("clientAgent", clientAgent);
        context.setItem("clientRateLimitTitle", "auth.client.check");
        context.setItem("clientJWTToken", token);

        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("authControllerFilters", "client/check")
                        .stream()
                        .filter(validationFilter -> validationFilter.canPassRequest(context))
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
            return possiblyErrorResponse.get().responseEntity();
        }

        var possiblyErrorInAction =
                httpAsyncActionConfigurer.provideActions("authControllerActions", "login")
                        .stream()
                        .parallel()
                        .peek(action -> action.perform(context))
                        .filter(action -> !action.hasSuccessfulFinished(context))
                        .map(action -> action.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorInAction.isPresent()) {
            return possiblyErrorInAction.get().responseEntity();
        }


        var message =
                ObjectLeaftBuilder.builder()
                        .put("isActiveSession", true)
                        .build();

        return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);
    }

    @DeleteMapping(value = "/logout", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> logout(
            @RequestHeader("User-Agent") String clientAgent,
            @RequestHeader("Authorization") String authorization
    ) {

        var token = authorization.replace("Bearer ", "").trim();

        try {
            bearerAuthenticationFactory.jwtTokenHandler().addToBlackList(token);
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {

            var message =
                    ObjectLeaftBuilder.builder()
                            .put("message", "There was an error in the application")
                            .build();

            return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @PostMapping(
            value = "/external-user/login",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> loginForExternalUser(
            @RequestHeader("User-Agent") String clientAgent,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,
            @RequestBody String body
    ) {

        var jsonBody = new JSONObject(body);

        var clientAddress = request.getRemoteAddr();
        String username = jsonBody.getString("clientUsername");
        String password = jsonBody.getString("clientPassword");

        var context = new EnvironmentContext();

        context.setItem("clientIP", clientAddress);
        context.setItem("clientAgent", clientAgent);
        context.setItem("clientCSRFToken", xCsrfToken);
        context.setItem("clientUsername", username);
        context.setItem("clientPassword", password);
        context.setItem("csrfToken", xCsrfToken);
        context.setItem("clientRateLimitTitle", "auth.external-user.login");

        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("authControllerFilters", "client/login")
                        .stream()
                        .filter(validationFilter -> validationFilter.canPassRequest(context))
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
            return possiblyErrorResponse.get().responseEntity();
        }

        var possiblyErrorInAction =
                httpAsyncActionConfigurer.provideActions("authControllerActions", "login")
                        .stream()
                        .parallel()
                        .peek(action -> action.perform(context))
                        .filter(action -> !action.hasSuccessfulFinished(context))
                        .map(action -> action.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorInAction.isPresent()) {
            return possiblyErrorInAction.get().responseEntity();
        }

        var jwtToken = (String) context.getItem("clientCredentialsAsyncFilter.jwtToken");

        var message =
                ObjectLeaftBuilder.builder()
                        .put("token", jwtToken)
                        .build();

        return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

    }

    @PostMapping(value = "/external-user/check", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> checkForExternalUser(
            @RequestHeader("User-Agent") String clientAgent,
            @RequestHeader("Authorization") String authorization,
            @RequestBody String body
    ) {

        var jsonBody = new JSONObject(body);

        var token = authorization.replace("Bearer ", "").trim();

        var clientAddress = request.getRemoteAddr();

        var context = new EnvironmentContext();

        context.setItem("clientIP", clientAddress);
        context.setItem("clientAgent", clientAgent);
        context.setItem("clientRateLimitTitle", "auth.client.check");
        context.setItem("clientJWTToken", token);


        context.setItem("externalUserIP", jsonBody.getString("externalUserIP"));
        context.setItem("externalUserAgent", jsonBody.getString("externalUserAgent"));
        context.setItem("externalUserRateLimitTitle", "auth.external-user.check");
        context.setItem("externalUserJWTToken", jsonBody.getString("externalUserJWTToken"));

        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("authControllerFilters", "client/check")
                        .stream()
                        .filter(validationFilter -> validationFilter.canPassRequest(context))
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
            return possiblyErrorResponse.get().responseEntity();
        }

        var possiblyErrorInAction =
                httpAsyncActionConfigurer.provideActions("authControllerActions", "login")
                        .stream()
                        .parallel()
                        .peek(action -> action.perform(context))
                        .filter(action -> !action.hasSuccessfulFinished(context))
                        .map(action -> action.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorInAction.isPresent()) {
            return possiblyErrorInAction.get().responseEntity();
        }


        var message =
                ObjectLeaftBuilder.builder()
                        .put("isActiveSession", true)
                        .build();

        return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);
    }

}
