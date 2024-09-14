package org.makechtec.web.authentication_gateway.http.auth;


import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.asyn_http.HttpAsyncActionConfigurer;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationFilterConfigurer;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final BearerAuthenticationFactory bearerAuthenticationFactory;
    private final CSRFTokenHandler csrfTokenHandler;
    private final RateLimiter rateLimiter;
    private final HttpServletRequest request;
    private final CommonResponseBuilder commonResponseBuilder = new CommonResponseBuilder();
    private final RequestValidationFilterConfigurer requestValidationFilterConfigurer = new RequestValidationFilterConfigurer();
    private final HttpAsyncActionConfigurer httpAsyncActionConfigurer;

    @Autowired
    public AuthController(@Qualifier("bearerAuthenticationFactory") BearerAuthenticationFactory bearerAuthenticationFactory, CSRFTokenHandler csrfTokenHandler, RateLimiter rateLimiter, HttpServletRequest request, HttpAsyncActionConfigurer httpAsyncActionConfigurer) {
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
        this.csrfTokenHandler = csrfTokenHandler;
        this.rateLimiter = rateLimiter;
        this.request = request;
        this.httpAsyncActionConfigurer = httpAsyncActionConfigurer;
    }

    @PostMapping(value = "/login", produces = MediaType.APPLICATION_JSON_VALUE, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> loginByUserRequest(
            @RequestHeader("Authorization") String authorization,
            @RequestBody String body
    ) {

        var jsonBody = new JSONObject(body);

        var clientAddress = request.getRemoteAddr();
        String userAgent = jsonBody.getString("userAgent");
        String userIP = jsonBody.getString("userAddress");
        String xCsrfToken = jsonBody.getString("csrfToken");
        String username = jsonBody.getString("username");
        String password = jsonBody.getString("password");

        var context = new EnvironmentContext();

        context.setItem("clientAddress", clientAddress);
        context.setItem("userAddress", userIP);
        context.setItem("userAgent", userAgent);
        context.setItem("username", username);
        context.setItem("password", password);
        context.setItem("csrfToken", xCsrfToken);
        context.setItem("rateLimitTitle", "login");

        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("authControllerFilters", "login")
                        .stream()
                        .filter(validationFilter -> validationFilter.canPassRequest(context))
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
            return possiblyErrorResponse.get().responseEntity();
        }

        var possiblyErrorInAction =
                httpAsyncActionConfigurer.provideActions("adminControllerActions", "login")
                        .stream()
                        .parallel()
                        .peek(action -> action.perform(context))
                        .filter(action -> !action.hasSuccessfulFinished(context))
                        .map(action -> action.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorInAction.isPresent()) {
            return possiblyErrorInAction.get().responseEntity();
        }

        var jwtToken = (String) context.getItem("jwtToken");

        var message =
                ObjectLeaftBuilder.builder()
                        .put("token", jwtToken)
                        .build();

        return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

    }

    @GetMapping(value = "/check", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> checkToken(@RequestHeader("Authorization") String authorization) {
        var token = authorization.replace("Bearer ", "").trim();

        try {
            if (bearerAuthenticationFactory.jwtTokenHandler().isInBlackList(token)) {
                var message =
                        ObjectLeaftBuilder.builder()
                                .put("isValid", false)
                                .build();

                return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
            }
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            var message =
                    ObjectLeaftBuilder.builder()
                            .put("message", "There was an error in the application")
                            .build();

            return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        var isValidToken = bearerAuthenticationFactory.jwtTokenHandler().isValidSignature(token);

        var message =
                ObjectLeaftBuilder.builder()
                        .put("isValid", isValidToken)
                        .build();

        return isValidToken ? new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK) :
                new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
    }

    @DeleteMapping(value = "/logout", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authorization) {

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

}
