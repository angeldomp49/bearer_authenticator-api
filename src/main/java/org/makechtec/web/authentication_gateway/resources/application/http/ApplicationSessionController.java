package org.makechtec.web.authentication_gateway.resources.application.http;

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
            @RequestParam("secretKey") String secretKey
    ) {

        var applicationIP = request.getRemoteAddr();

        try {

            var rateLimitInformation = new HashMap<String, String>();

            rateLimitInformation.put("applicationIP", applicationIP);
            rateLimitInformation.put("applicationAgent", applicationAgent);

            var temporaryApplicationSecretKey = cacheSystemTable.request("temporaryApplicationSecretKey");

            final var rateLimitValidationFuture = CompletableFuture.runAsync(() -> {
                var initTime = System.currentTimeMillis();
                final var result = !controllerValidatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);
                var finalTime = System.currentTimeMillis();

                System.out.println("rateLimitValidationFuture time: " + (finalTime - initTime));
                if (result) {
                    throw new ParallelValidationException(
                            new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS)
                    );
                }
            });

            final var csrfValidationFuture = CompletableFuture.runAsync(() -> {
                var initTime = System.currentTimeMillis();
                final var result = controllerValidatorFactory.getCSRFValidator().nonValidCSRF(applicationXCsrfToken, temporaryApplicationSecretKey);
                var finalTime = System.currentTimeMillis();

                System.out.println("csrfValidationFuture time: " + (finalTime - initTime));
                if (result) {
                    throw new ParallelValidationException(
                            new ResponseEntity<>(HttpStatus.UNAUTHORIZED)
                    );
                }
            });

            final var sessionValidationFuture = CompletableFuture.runAsync(() -> {
                var initTime = System.currentTimeMillis();
                final var result = !controllerValidatorFactory.getSessionAuthenticator().areValidCredentials(accessKey, secretKey, RESOURCE_KIND);
                var finalTime = System.currentTimeMillis();

                System.out.println("sessionValidationFuture time: " + (finalTime - initTime));
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
                var initTime = System.currentTimeMillis();
                final var result = controllerValidatorFactory.getIPBlackListValidator().isForbiddenIP(applicationIP, IP_TAG);
                var finalTime = System.currentTimeMillis();

                System.out.println("iPValidationFuture time: " + (finalTime - initTime));
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

            var initTime = System.currentTimeMillis();
            final var session = controllerValidatorFactory.getSessionAuthenticator().createSession(accessKey);
            final var token = controllerValidatorFactory.getSessionAuthenticator().createJWT(session);
            var finalTime = System.currentTimeMillis();

            System.out.println("session token time: " + (finalTime - initTime));

            final var message = ObjectLeafBuilder.builder()
                    .put("token", token)
                    .build();


            sumOneAttemptFuture.join();

            return new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

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
