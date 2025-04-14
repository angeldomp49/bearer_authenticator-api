package org.makechtec.web.authentication_gateway.resources.client.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.bearer_authentication.tools.bearer.stateless.csrf.CSRFTokenGenerator;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.resources.client.validation.ClientRateLimitValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.logging.Logger;

@RequestMapping("client/session")
public class ClientSessionController {

    private static final Logger LOG = Logger.getLogger(ClientSessionController.class.getName());

    private final ClientRateLimitValidator clientRateLimitValidator;
    private final BearerAuthenticationFactory bearerAuthenticationFactory;
    private final CSRFTokenGenerator csrfTokenGenerator;
    private final HttpServletRequest request;
    private final CommonResponseBuilder commonResponseBuilder = new CommonResponseBuilder();

    public ClientSessionController(ClientRateLimitValidator clientRateLimitValidator, BearerAuthenticationFactory bearerAuthenticationFactory, CSRFTokenGenerator csrfTokenGenerator, HttpServletRequest request) {
        this.clientRateLimitValidator = clientRateLimitValidator;
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
        this.csrfTokenGenerator = csrfTokenGenerator;
        this.request = request;
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginByUserRequest(
            @RequestHeader("Client-Address") String clientIP,
            @RequestHeader("Client-Agent") String clientAgent,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,

            @RequestParam("username") String username,
            @RequestParam("password") String password
    ) {

        var applicationIP = request.getRemoteAddr();

        try {

            if (!this.clientRateLimitValidator.hasAttemptsThisClient(applicationIP, clientIP, clientAgent, "login")) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            this.clientRateLimitValidator.pushAttemptToThisClient(applicationIP, clientIP, clientAgent);

            if (!this.csrfTokenGenerator.isValidCSRFToken(xCsrfToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var areValidCredentials = bearerAuthenticationFactory.userAuthenticator().areValidCredentials(username, password);

            if (!areValidCredentials) {
                var message =
                        ObjectLeafBuilder.builder()
                                .put("message", "Username or password are invalid")
                                .build();

                return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
            }

            var session = bearerAuthenticationFactory.sessionGenerator().createForUser(username);
            var token = bearerAuthenticationFactory.jwtTokenHandler().createTokenForSession(session);

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

        try {
            if (bearerAuthenticationFactory.jwtTokenHandler().isInBlackList(token)) {
                var message =
                        ObjectLeafBuilder.builder()
                                .put("isValid", false)
                                .build();

                return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.OK);
            }
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            var message =
                    ObjectLeafBuilder.builder()
                            .put("message", "There was an error in the application")
                            .build();

            return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        var isValidToken = bearerAuthenticationFactory.jwtTokenHandler().isValidSignature(token);

        var message =
                ObjectLeafBuilder.builder()
                        .put("isValid", isValidToken)
                        .build();

        return isValidToken ? new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK) :
                new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
    }

    @DeleteMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String authorization) {

        var token = authorization.replace("Bearer ", "").trim();

        try {
            bearerAuthenticationFactory.jwtTokenHandler().addToBlackList(token);
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

}
