package org.makechtec.web.authentication_gateway.resources.application.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasher;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;
import org.makechtec.bearer_authentication.tools.bearer.stateless.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.resources.application.api.ApplicationDBConnection;
import org.makechtec.web.authentication_gateway.resources.application.api.ApplicationModel;
import org.makechtec.web.authentication_gateway.resources.application.session.ApplicationAuthenticator;
import org.makechtec.web.authentication_gateway.resources.application.validation.ApplicationRateLimitValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;

@RestController
@RequestMapping("application/api")
public class ApplicationAPIResourceController {

    private final PasswordHasher passwordHasher;
    private final SaltGenerator saltGenerator = new SaltGenerator();
    private final HttpServletRequest request;
    private final ApplicationRateLimitValidator rateLimitValidator;
    private final CSRFTokenGenerator csrfTokenGenerator;
    private final ApplicationAuthenticator authenticator;
    private final ApplicationDBConnection applicationDBConnection;


    public ApplicationAPIResourceController(PasswordHasher passwordHasher, HttpServletRequest request, ApplicationRateLimitValidator rateLimitValidator, CSRFTokenGenerator csrfTokenGenerator, ApplicationAuthenticator authenticator, ApplicationDBConnection applicationDBConnection) {
        this.passwordHasher = passwordHasher;
        this.request = request;
        this.rateLimitValidator = rateLimitValidator;
        this.csrfTokenGenerator = csrfTokenGenerator;
        this.authenticator = authenticator;
        this.applicationDBConnection = applicationDBConnection;
    }

    @PostMapping
    public ResponseEntity<String> store(
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,
            @RequestHeader("Authorization") String authorization,

            @RequestParam("accessKey") String accessKey,
            @RequestParam("secret") String password
    ) {
        var applicationIP = request.getRemoteAddr();

        var token = authorization.replace("Bearer ", "").trim();

        try {

            if (!this.rateLimitValidator.hasAttemptsThisClient(applicationIP, userAgent, "application")) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            rateLimitValidator.pushAttemptToThisClient(applicationIP, userAgent);

            if (!csrfTokenGenerator.isValidCSRFToken(xCsrfToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            if (!authenticator.isValidJWTSignature(token)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var salt = saltGenerator.generate();

            var rawHashed = passwordHasher.rawHashNotIncludingSalt(password, salt);

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
