package org.makechtec.web.authentication_gateway.resources.application.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.bearer_authentication.tools.bearer.stateless.csrf.CSRFTokenGenerator;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.resources.application.session.ApplicationAuthenticator;
import org.makechtec.web.authentication_gateway.resources.application.validation.ApplicationRateLimitValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.logging.Logger;

@RequestMapping("application/session")
public class ApplicationSessionController {

    private static final Logger LOG = Logger.getLogger(ApplicationSessionController.class.getName());

    private final ApplicationRateLimitValidator applicationRateLimitValidator;
    private final ApplicationAuthenticator authenticator;
    private final CSRFTokenGenerator csrfTokenGenerator;
    private final HttpServletRequest request;
    private final CommonResponseBuilder commonResponseBuilder = new CommonResponseBuilder();

    public ApplicationSessionController(ApplicationRateLimitValidator applicationRateLimitValidator, ApplicationAuthenticator authenticator, CSRFTokenGenerator csrfTokenGenerator, HttpServletRequest request) {
        this.applicationRateLimitValidator = applicationRateLimitValidator;
        this.authenticator = authenticator;
        this.csrfTokenGenerator = csrfTokenGenerator;
        this.request = request;
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginByUserRequest(
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,

            @RequestParam("accessKey") String accessKey,
            @RequestParam("secret") String secret
    ) {

        var userIP = request.getRemoteAddr();

        try {

            if (!this.applicationRateLimitValidator.hasAttemptsThisClient(userIP, userAgent, "login")) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            this.applicationRateLimitValidator.pushAttemptToThisClient(userIP, userAgent);

            if (!this.csrfTokenGenerator.isValidCSRFToken(xCsrfToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var areValidCredentials = authenticator.areValidCredentials(accessKey, secret);

            if (!areValidCredentials) {
                var message =
                        ObjectLeafBuilder.builder()
                                .put("message", "Username or password are invalid")
                                .build();

                return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
            }

            var session = authenticator.createSession(accessKey);
            var token = authenticator.createJWT(session);

            var message =
                    ObjectLeafBuilder.builder()
                            .put("token", token)
                            .build();

            return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            var message =
                    ObjectLeafBuilder.builder()
                            .put("message", "There was an error in the application")
                            .build();

            return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/check")
    public ResponseEntity<String> checkToken(
            @RequestHeader("Authorization") String authorization
    ) {
        var token = authorization.replace("Bearer ", "").trim();


        boolean isValidToken = false;
        try {
            isValidToken = authenticator.isValidJWTSignature(token);
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        var message =
                ObjectLeafBuilder.builder()
                        .put("isValid", isValidToken)
                        .build();

        return isValidToken ? new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK) :
                new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
    }

    @DeleteMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorization) {

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

}
