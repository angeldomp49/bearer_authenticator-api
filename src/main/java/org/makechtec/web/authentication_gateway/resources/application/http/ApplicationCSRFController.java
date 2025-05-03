package org.makechtec.web.authentication_gateway.resources.application.http;

import com.google.errorprone.annotations.Var;
import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.ParallelValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.ResultSet;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

@RequestMapping("application/csrf")
@RestController
public class ApplicationCSRFController {

    public static final String RATE_LIMIT_DEFINITION_NAME = "application-csrf-controller";
    public static final String IP_BLACKLIST_TAG = "application-ip-tag";
    private final ControllerValidatorFactory controllerValidatorFactory;
    private final CommonJSONResponseBuilder commonJSONResponseBuilder;
    private final HttpServletRequest request;
    private final CacheSystemTable cacheSystemTable;

    @Autowired
    public ApplicationCSRFController(ControllerValidatorFactory controllerValidatorFactory, CommonJSONResponseBuilder commonJSONResponseBuilder, HttpServletRequest request, CacheSystemTable cacheSystemTable) {
        this.controllerValidatorFactory = controllerValidatorFactory;
        this.commonJSONResponseBuilder = commonJSONResponseBuilder;
        this.request = request;
        this.cacheSystemTable = cacheSystemTable;
    }


    @GetMapping
    public ResponseEntity<String> getCSRF(
            @RequestHeader("Application-Agent") String applicationAgent
    ) {
        var applicationIP = request.getRemoteAddr();

        var rateLimitInformation = new HashMap<String, String>();

        rateLimitInformation.put("applicationIP", applicationIP);
        rateLimitInformation.put("applicationAgent", applicationAgent);

        var secretKey = cacheSystemTable.request("temporaryApplicationSecretKey");

        try {
            final var rateLimitValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = !controllerValidatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);
                
                if(result) {
                    throw new ParallelValidationException(
                            commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.TOO_MANY_REQUESTS)
                    );
                }
            });

            final var iPValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = !controllerValidatorFactory.getIPBlackListValidator().isValidIP(applicationIP, IP_BLACKLIST_TAG);

                if(result) {
                    throw new ParallelValidationException(
                            commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.UNAUTHORIZED)
                    );
                }
            });
            
            CompletableFuture.allOf(rateLimitValidationFuture, iPValidationFuture).join();


            
            final var sumOneAttemptFuture = CompletableFuture.runAsync(() ->
                    controllerValidatorFactory.getRateLimitValidator()
                            .sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME)
            );
            
            var token = controllerValidatorFactory.getCSRFValidator().generateCSRFToken(secretKey);

            var message =
                    ObjectLeafBuilder.builder()
                            .put("token", token)
                            .build();
            
            sumOneAttemptFuture.join();

            return new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK);

        } catch (ControllerValidationException e) {
            return commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (ParallelValidationException e) {
            return e.getResponse();
        } catch (CompletionException e) {
            return new ResponseEntity<>(
                    commonJSONResponseBuilder.createResponseWithMessage(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR),
                    HttpStatus.INTERNAL_SERVER_ERROR
            );
        }


    }

}
