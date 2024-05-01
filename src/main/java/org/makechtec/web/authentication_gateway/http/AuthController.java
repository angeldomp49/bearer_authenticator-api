package org.makechtec.web.authentication_gateway.http;


import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final BearerAuthenticationFactory bearerAuthenticationFactory;
    private final CSRFTokenHandler csrfTokenHandler;
    private final RateLimiter rateLimiter;

    @Autowired
    public AuthController(@Qualifier("bearerAuthenticationFactory") BearerAuthenticationFactory bearerAuthenticationFactory, CSRFTokenHandler csrfTokenHandler, RateLimiter rateLimiter) {
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
        this.csrfTokenHandler = csrfTokenHandler;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/login")
    public ResponseEntity<String> loginByUserRequest(
            @RequestHeader("User-Address") String userAddress,
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("Client-Address") String clientAddress,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,

            @RequestParam("username") String username,
            @RequestParam("password") String password
    ) {

        try {

            if (!this.rateLimiter.hasAttemptsThisClient(userAddress, userAgent, clientAddress, "login")) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            this.rateLimiter.pushAttemptToThisClient(userAddress, userAgent, clientAddress);

            if (!this.csrfTokenHandler.isValidCSRFToken(userAddress, userAgent, clientAddress, xCsrfToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var areValidCredentials = bearerAuthenticationFactory.userAuthenticator().areValidCredentials(username, password);

            if (!areValidCredentials) {
                var message =
                        ObjectLeaftBuilder.builder()
                                .put("message", "Username or password are invalid")
                                .build();

                return new ResponseEntity<>(createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
            }

            var session = bearerAuthenticationFactory.sessionGenerator().createForUser(username);
            var token = bearerAuthenticationFactory.jwtTokenHandler().createTokenForSession(session);

            var message =
                    ObjectLeaftBuilder.builder()
                            .put("token", token)
                            .build();

            return new ResponseEntity<>(createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            var message =
                    ObjectLeaftBuilder.builder()
                            .put("message", "There was an error in the application")
                            .build();

            return new ResponseEntity<>(createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/check")
    public ResponseEntity<String> checkToken(@RequestHeader("Authorization") String authorization) {
        var token = authorization.replace("Bearer ", "").trim();

        try {
            if (bearerAuthenticationFactory.jwtTokenHandler().isInBlackList(token)) {
                var message =
                        ObjectLeaftBuilder.builder()
                                .put("isValid", false)
                                .build();

                return new ResponseEntity<>(createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.OK);
            }
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            var message =
                    ObjectLeaftBuilder.builder()
                            .put("message", "There was an error in the application")
                            .build();

            return new ResponseEntity<>(createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }

        var isValidToken = bearerAuthenticationFactory.jwtTokenHandler().isValidSignature(token);

        var message =
                ObjectLeaftBuilder.builder()
                        .put("isValid", isValidToken)
                        .build();

        return isValidToken ? new ResponseEntity<>(createResponse(message, HttpStatus.OK), HttpStatus.OK) :
                new ResponseEntity<>(createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
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

    private String createResponse(ObjectLeaf content, HttpStatus status) {
        return
                ObjectLeaftBuilder.builder()
                        .put("statusCode", status.value())
                        .put("body",
                                ObjectLeaftBuilder.builder()
                                        .put("data",
                                                content
                                        )
                                        .build()
                        )
                        .build()
                        .getLeafValue();
    }

}
