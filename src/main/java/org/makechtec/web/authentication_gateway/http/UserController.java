package org.makechtec.web.authentication_gateway.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.web.authentication_gateway.api.user.StoredUserModel;
import org.makechtec.web.authentication_gateway.api.user.UserDBConnection;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.password.SaltGenerator;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.Objects;

@RestController
@RequestMapping("user")
public class UserController {

    private final UserDBConnection userDBConnection;
    private final PasswordHasher passwordHasher;
    private final SaltGenerator saltGenerator = new SaltGenerator();
    private final HttpServletRequest request;
    private final RateLimiter rateLimiter;
    private final CSRFTokenHandler csrfTokenHandler;

    private final BearerAuthenticationFactory bearerAuthenticationFactory;

    public UserController(@Qualifier("userDBConnection") UserDBConnection userDBConnection, PasswordHasher passwordHasher, HttpServletRequest request, RateLimiter rateLimiter, CSRFTokenHandler csrfTokenHandler, @Qualifier("bearerAuthenticationFactory") BearerAuthenticationFactory bearerAuthenticationFactory) {
        this.userDBConnection = userDBConnection;
        this.passwordHasher = passwordHasher;
        this.request = request;
        this.rateLimiter = rateLimiter;
        this.csrfTokenHandler = csrfTokenHandler;
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
    }

    @PostMapping
    public ResponseEntity<Void> store(
            @RequestHeader(name = "User-Address", required = false) String userAddress,
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("Client-Address") String clientAddress,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,
            @RequestHeader("Authorization") String authorization,

            @RequestParam("username") String username,
            @RequestParam("email") String email,
            @RequestParam("password") String password
    ) {

        var userIP = (Objects.isNull(userAddress)) ? request.getRemoteAddr() : userAddress;

        var token = authorization.replace("Bearer ", "").trim();
        try {

            if (!this.rateLimiter.hasAttemptsThisClient(userIP, userAgent, clientAddress, "csrf")) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            this.rateLimiter.pushAttemptToThisClient(userIP, userAgent, clientAddress);

            if (!this.csrfTokenHandler.isValidCSRFToken(userIP, userAgent, clientAddress, xCsrfToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            this.csrfTokenHandler.deleteCSRFToken(xCsrfToken);

            if (
                    bearerAuthenticationFactory.jwtTokenHandler().isInBlackList(token) ||
                            (!bearerAuthenticationFactory.jwtTokenHandler().isValidSignature(token))
            ) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var salt = saltGenerator.generate();
            userDBConnection.store(new StoredUserModel(
                    username,
                    email,
                    passwordHasher.hash(password),
                    salt
            ));

            return new ResponseEntity<>(HttpStatus.CREATED);
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
