package org.makechtec.web.authentication_gateway.resources.client.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

@RequestMapping("client/csrf")
@RestController
public class ClientCSRFController {

    public static final String RATE_LIMIT_DEFINITION_NAME = "client-csrf-controller";
    public static final String APPLICATION_IP_TAG = "application-ip-tag";
    public static final String CLIENT_IP_TAG = "client-ip-tag";
    private static final Logger LOG = Logger.getLogger(ClientCSRFController.class.getName());
    private final HttpServletRequest request;
    private final CommonJSONResponseBuilder responseBuilder;
    private final ControllerValidatorFactory validatorFactory;

    @Autowired
    public ClientCSRFController(HttpServletRequest request, CommonJSONResponseBuilder responseBuilder, ControllerValidatorFactory validatorFactory) {
        this.request = request;
        this.responseBuilder = responseBuilder;
        this.validatorFactory = validatorFactory;
    }


    @GetMapping
    public ResponseEntity<String> getCSRF(
            @RequestHeader("Client-Agent") String clientAgent,
            @RequestHeader("Client-Address") String clientIP,

            @RequestHeader("Application-Authorization") String applicationAuthorization
    ) {
        var applicationIP = request.getRemoteAddr();


        try {

            var applicationToken = applicationAuthorization.replace("Bearer ", "").trim();

            var rateLimitInformation = new HashMap<String, String>();

            rateLimitInformation.put("applicationIP", applicationIP);
            rateLimitInformation.put("clientIP", clientIP);
            rateLimitInformation.put("clientAgent", clientAgent);

            if (!validatorFactory.getSessionAuthenticator().isValidJWTSignature(applicationToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            CompletableFuture<Boolean> rateLimitFuture = CompletableFuture.supplyAsync(() -> {

                try {
                    return validatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);
                } catch (ControllerValidationException e) {
                    return false;
                }
            });

            CompletableFuture<String> tokenFuture = CompletableFuture.supplyAsync(validatorFactory.getCSRFValidator()::generateCSRFToken);


            var isAllowed = validatorFactory.getIPBlackListValidator().isValidIP(applicationIP, APPLICATION_IP_TAG)
                    && validatorFactory.getIPBlackListValidator().isValidIP(clientIP, CLIENT_IP_TAG);

            if (!isAllowed) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            if (!rateLimitFuture.join()) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            var token = tokenFuture.join();

            CompletableFuture.supplyAsync(() -> {
                try {
                    validatorFactory.getRateLimitValidator().sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);
                    return null;
                } catch (ControllerValidationException e) {
                    LOG.severe("Error pushing attempt for client: " + e.getMessage());
                    return null;
                }
            });

            var message =
                    ObjectLeafBuilder.builder()
                            .put("token", token)
                            .build();

            return new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK);

        } catch (ControllerValidationException e) {
            LOG.severe("Error generating CSRF token: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }


    }

}
