package org.makechtec.web.authentication_gateway.resources.application.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.components.random_string.RandomStringGenerator;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

@RequestMapping("application/csrf")
public class ApplicationCSRFController {

    public static final String RATE_LIMIT_DEFINITION_NAME = "application-csrf-controller";
    private static final Logger LOG = Logger.getLogger(ApplicationCSRFController.class.getName());
    private final ControllerValidatorFactory controllerValidatorFactory;
    private final CommonJSONResponseBuilder commonJSONResponseBuilder;
    private final HttpServletRequest request;
    private final CacheSystemTable cacheSystemTable;
    private final RandomStringGenerator randomStringGenerator;

    @Autowired
    public ApplicationCSRFController(ControllerValidatorFactory controllerValidatorFactory, CommonJSONResponseBuilder commonJSONResponseBuilder, HttpServletRequest request, CacheSystemTable cacheSystemTable, RandomStringGenerator randomStringGenerator) {
        this.controllerValidatorFactory = controllerValidatorFactory;
        this.commonJSONResponseBuilder = commonJSONResponseBuilder;
        this.request = request;
        this.cacheSystemTable = cacheSystemTable;
        this.randomStringGenerator = randomStringGenerator;
    }


    @GetMapping
    public ResponseEntity<String> getCSRF(
            @RequestHeader("Application-Agent") String applicationAgent
    ) {
        var applicationIP = request.getRemoteAddr();

        var rateLimitInformation = new HashMap<String, String>();

        rateLimitInformation.put("applicationIP", applicationIP);
        rateLimitInformation.put("applicationAgent", applicationAgent);

        try {

            CompletableFuture<Boolean> rateLimitFuture = CompletableFuture.supplyAsync(() -> {
                try {

                    return controllerValidatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);
                } catch (ControllerValidationException e) {
                    return false;
                }
            });

            CompletableFuture<String> tokenFuture = CompletableFuture.supplyAsync(() -> {
                if(!cacheSystemTable.contains("temporaryApplicationSecretKey")) {
                    cacheSystemTable.put("temporaryApplicationSecretKey", randomStringGenerator.generateTemporarySecretKey());
                }

                return controllerValidatorFactory.getCSRFValidator().generateCSRFToken(cacheSystemTable.request("temporaryApplicationSecretKey"));
            });


            var isAllowed = controllerValidatorFactory.getIPBlackListValidator().isValidIP(applicationIP);

            if (!isAllowed) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            if (!rateLimitFuture.join()) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            var token = tokenFuture.join();

            CompletableFuture.supplyAsync(() -> {
                try {
                    controllerValidatorFactory.getRateLimitValidator().sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);
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

            return new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK);

        } catch (ControllerValidationException e) {
            LOG.severe("Error generating CSRF token: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }


    }

}
