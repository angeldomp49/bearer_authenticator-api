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
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.logging.Logger;

@RequestMapping("application/session")
@RestController
public class ApplicationSessionController {

    public static final String RATE_LIMIT_DEFINITION_NAME = "application-session-controller";
    public static final String RESOURCE_KIND = "application";
    public static final String IP_TAG = "application-ip-tag";
    private final ControllerValidatorFactory controllerValidatorFactory;
    private final HttpServletRequest request;
    private final CommonJSONResponseBuilder commonJSONResponseBuilder;
    private final CacheSystemTable cacheSystemTable;

    @Autowired
    public ApplicationSessionController(ControllerValidatorFactory controllerValidatorFactory, HttpServletRequest request, CommonJSONResponseBuilder commonJSONResponseBuilder, CacheSystemTable cacheSystemTable) {
        this.controllerValidatorFactory = controllerValidatorFactory;
        this.request = request;
        this.commonJSONResponseBuilder = commonJSONResponseBuilder;
        this.cacheSystemTable = cacheSystemTable;
    }


    @PostMapping("/login")
    public ResponseEntity<String> loginByUserRequest(
            @RequestHeader("Application-Agent") String applicationAgent,
            @RequestHeader("Application-X-Csrf-Token") String applicationXCsrfToken,

            @RequestParam("accessKey") String accessKey,
            @RequestParam("secret") String secret
    ) {

        var applicationIP = request.getRemoteAddr();

        try {

            var rateLimitInformation = new HashMap<String, String>();

            rateLimitInformation.put("applicationIP", applicationIP);
            rateLimitInformation.put("applicationAgent", applicationAgent);

            var secretKey = cacheSystemTable.request("temporaryApplicationSecretKey");
            
            final var rateLimitValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = !controllerValidatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);
                if (result) {
                    throw new ParallelValidationException(
                            new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS)
                    );
                }
            });

            final var csrfValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = !controllerValidatorFactory.getCSRFValidator().nonValidCSRF(applicationXCsrfToken, secretKey);
                if (result) {
                    throw new ParallelValidationException(
                            new ResponseEntity<>(HttpStatus.UNAUTHORIZED)
                    );
                }
            });

            final var sessionValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = !controllerValidatorFactory.getSessionAuthenticator().areValidCredentials(accessKey, secret, RESOURCE_KIND);
                if (result) {

                    var message =
                            ObjectLeafBuilder.builder()
                                    .put("message", "Username or password are invalid")
                                    .build();
                    
                    throw new ParallelValidationException(
                            new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED)
                    );
                }
            });
            
            final var iPValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = !controllerValidatorFactory.getIPBlackListValidator().isValidIP(applicationIP, IP_TAG);
                
                if (result) {

                    throw new ParallelValidationException(
                            commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.UNAUTHORIZED)
                    );
                }
            });
            
            
            
            CompletableFuture.allOf(rateLimitValidationFuture, csrfValidationFuture, sessionValidationFuture, iPValidationFuture).join();

            
            final var sumOneAttemptFuture = CompletableFuture.runAsync(() ->
                    controllerValidatorFactory.getRateLimitValidator().sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME)
            );

            final var session = controllerValidatorFactory.getSessionAuthenticator().createSession(accessKey);
            final var token = controllerValidatorFactory.getSessionAuthenticator().createJWT(session);

            final var message = ObjectLeafBuilder.builder()
                            .put("token", token)
                            .build();
            

            sumOneAttemptFuture.join();

            return new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

        } catch (ControllerValidationException e) {
            return commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.INTERNAL_SERVER_ERROR);
        } catch (ParallelValidationException e) {
            return e.getResponse();
        }  catch (CompletionException e) {
            return new ResponseEntity<>(
                    commonJSONResponseBuilder.createResponseWithMessage(e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR),
                    HttpStatus.INTERNAL_SERVER_ERROR
            );
        }

    }

    @GetMapping("/check")
    public ResponseEntity<String> checkToken(
            @RequestHeader("Application-Authorization") String applicationAuthorization
    ) {
        var token = applicationAuthorization.replace("Bearer ", "").trim();


        boolean isValidToken;

        try {
            isValidToken = controllerValidatorFactory.getSessionAuthenticator().isValidJWTSignature(token);
        } catch (ControllerValidationException e) {
            return commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.UNAUTHORIZED);
        }

        var message =
                ObjectLeafBuilder.builder()
                        .put("isValid", isValidToken)
                        .build();

        return isValidToken ? new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK) :
                commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.UNAUTHORIZED);
    }


}
