package org.makechtec.web.authentication_gateway.resources.application.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasher;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.makechtec.web.authentication_gateway.resources.application.api.ApplicationDBConnection;
import org.makechtec.web.authentication_gateway.resources.application.api.ApplicationModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.HashMap;

@RestController
@RequestMapping("application/api")
public class ApplicationAPIResourceController {

    public static final String RATE_LIMIT_DEFINITION_NAME = "application-api-controller";
    private final PasswordHasher passwordHasher;
    private final SaltGenerator saltGenerator = new SaltGenerator();
    private final HttpServletRequest request;
    private final ControllerValidatorFactory validatorFactory;
    private final ApplicationDBConnection applicationDBConnection;

    @Autowired
    public ApplicationAPIResourceController(PasswordHasher passwordHasher, HttpServletRequest request, ControllerValidatorFactory validatorFactory, ApplicationDBConnection applicationDBConnection) {
        this.passwordHasher = passwordHasher;
        this.request = request;
        this.validatorFactory = validatorFactory;
        this.applicationDBConnection = applicationDBConnection;
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

        var token = applicationAuthorization.replace("Bearer ", "").trim();

        try {

            var rateLimitInformation = new HashMap<String, String>();

            rateLimitInformation.put("applicationIP", applicationIP);
            rateLimitInformation.put("applicationAgent", applicationAgent);

            if (!validatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME)) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            validatorFactory.getRateLimitValidator().sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);

            if (!validatorFactory.getCSRFValidator().isValidCSRF(applicationXCsrfToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            if (!validatorFactory.getSessionAuthenticator().isValidJWTSignature(token)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var salt = saltGenerator.generate();

            var rawHashed = passwordHasher.rawHashNotIncludingSalt(secret, salt);

            applicationDBConnection.store(new ApplicationModel(
                    accessKey,
                    rawHashed,
                    salt
            ));

            return new ResponseEntity<>(HttpStatus.CREATED);

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
