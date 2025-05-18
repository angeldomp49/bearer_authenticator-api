package org.makechtec.web.authentication_gateway.resources.application.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.ParallelValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.makechtec.web.authentication_gateway.resources.application.api.ApplicationDBConnection;
import org.makechtec.web.authentication_gateway.resources.application.api.ApplicationModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.concurrent.CompletableFuture;

@RestController
@RequestMapping("application/api")
public class ApplicationAPIResourceController {

    public static final String RATE_LIMIT_DEFINITION_NAME = "application-api-controller";
    private final PasswordHasherNative passwordHasher;
    private final SaltGenerator saltGenerator = new SaltGenerator();
    private final HttpServletRequest request;
    private final ControllerValidatorFactory validatorFactory;
    private final CommonJSONResponseBuilder commonJSONResponseBuilder;
    private final ApplicationDBConnection applicationDBConnection;
    private final CacheSystemTable cacheSystemTable;

    @Autowired
    public ApplicationAPIResourceController(PasswordHasherNative passwordHasher, HttpServletRequest request, ControllerValidatorFactory validatorFactory, CommonJSONResponseBuilder commonJSONResponseBuilder, ApplicationDBConnection applicationDBConnection, CacheSystemTable cacheSystemTable) {
        this.passwordHasher = passwordHasher;
        this.request = request;
        this.validatorFactory = validatorFactory;
        this.commonJSONResponseBuilder = commonJSONResponseBuilder;
        this.applicationDBConnection = applicationDBConnection;
        this.cacheSystemTable = cacheSystemTable;
    }


    @PostMapping
    public ResponseEntity<String> store(
            @RequestHeader("Application-Agent") String applicationAgent,
            @RequestHeader("Application-X-Csrf-Token") String applicationXCsrfToken,
            @RequestHeader("Application-Authorization") String applicationAuthorization,

            @RequestParam("accessKey") String accessKey,
            @RequestParam("secret") String secret
    ) {
        var applicationIP = request.getRemoteAddr();

        var sessionToken = applicationAuthorization.replace("Bearer ", "").trim();

        var secretKey = cacheSystemTable.request("temporaryApplicationSecretKey");

        var rateLimitInformation = new HashMap<String, String>();

        rateLimitInformation.put("applicationIP", applicationIP);
        rateLimitInformation.put("applicationAgent", applicationAgent);

        try {

            final var rateLimitValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = !validatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);

                if (result) {
                    throw new ParallelValidationException(
                            commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.TOO_MANY_REQUESTS)
                    );
                }
            });

            final var csrfValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = validatorFactory.getCSRFValidator().nonValidCSRF(applicationXCsrfToken, secretKey);
                if (result) {
                    throw new ParallelValidationException(
                            new ResponseEntity<>(HttpStatus.UNAUTHORIZED)
                    );
                }
            });

            final var sessionValidationFuture = CompletableFuture.runAsync(() -> {
                final var result = !validatorFactory.getSessionAuthenticator().isValidJWTSignature(sessionToken);
                if (result) {
                    throw new ParallelValidationException(
                            new ResponseEntity<>(HttpStatus.UNAUTHORIZED)
                    );
                }
            });

            CompletableFuture.allOf(rateLimitValidationFuture, csrfValidationFuture, sessionValidationFuture).join();

            final var sumOneAttemptFuture = CompletableFuture.runAsync(() ->
                    validatorFactory.getRateLimitValidator().sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME)
            );

            var salt = saltGenerator.generate();

            var rawHashed = passwordHasher.rawHash(secret, salt);

            applicationDBConnection.store(new ApplicationModel(
                    accessKey,
                    rawHashed,
                    salt
            ));

            sumOneAttemptFuture.join();

            return commonJSONResponseBuilder.createResponseWithStatus(HttpStatus.CREATED);

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
