package org.makechtec.web.authentication_gateway.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.SQLException;
import java.util.Calendar;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

@RestController
@RequestMapping("csrf")
public class CSRFController {

    private static final Logger LOG = Logger.getLogger(CSRFController.class.getName());
    private final ClientValidator clientValidator;
    private final CSRFTokenHandler csrfTokenHandler;
    private final HttpServletRequest request;
    private final CommonResponseBuilder responseBuilder;
    private final RateLimiter rateLimiter;
    private final CSRFTokenGenerator csrfTokenGenerator;

    private boolean haveSuccededAllServices;

    public CSRFController(ClientValidator clientValidator, CSRFTokenHandler csrfTokenHandler, HttpServletRequest request, CommonResponseBuilder responseBuilder, RateLimiter rateLimiter, CSRFTokenGenerator csrfTokenGenerator) {
        this.clientValidator = clientValidator;
        this.csrfTokenHandler = csrfTokenHandler;
        this.request = request;
        this.responseBuilder = responseBuilder;
        this.rateLimiter = rateLimiter;
        this.csrfTokenGenerator = csrfTokenGenerator;
    }

    @PostMapping(value = "/client/public", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> generateCSRFTokenForClient(
            @RequestHeader(name = "User-Address", required = false) String userAddress,
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("Client-Address") String clientAddress
    ) {

        var userIP = (Objects.isNull(userAddress)) ? request.getRemoteAddr() : userAddress;
        var expirationDate = Calendar.getInstance();

        try {

            CompletableFuture<Boolean> rateLimitFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return this.rateLimiter.hasAttemptsThisClient(userIP, userAgent, clientAddress, "csrf");
                } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                    return false;
                }
            });

            CompletableFuture<String> tokenFuture = CompletableFuture.supplyAsync(() -> {

                expirationDate.add(Calendar.MINUTE, 30);

                return this.csrfTokenGenerator.generateCSRFToken();
            });

            var isAllowed = false;

            try {
                isAllowed = this.clientValidator.isAllowedClient(clientAddress);
            } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                LOG.severe("This client is not allowed due error in connection: " + e.getMessage());
            }


            if (!isAllowed) {

                var message =
                        ObjectLeaftBuilder.builder()
                                .put("message", "Unauthorized, this client is not allowed")
                                .build();

                return new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
            }

            if (!rateLimitFuture.join()) {

                var message =
                        ObjectLeaftBuilder.builder()
                                .put("message", "This client has too many requests")
                                .build();

                return new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.TOO_MANY_REQUESTS), HttpStatus.TOO_MANY_REQUESTS);
            }

            var token = tokenFuture.join();

            CompletableFuture<Boolean> pusthAttemptFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    this.rateLimiter.pushAttemptToThisClient(userIP, userAgent, clientAddress);
                    return true;
                } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                    LOG.severe("Error pushing attempt for client: " + e.getMessage());
                    return false;
                }
            });

            CompletableFuture<Boolean> registerCSRFFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    this.csrfTokenHandler.registerCSRFToken(userIP, userAgent, clientAddress, expirationDate.getTimeInMillis(), token);
                    return true;
                } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                    LOG.severe("Error registering token: " + e.getMessage());
                    return false;
                }
            });

            var pushAttemptResult = pusthAttemptFuture.join();
            var registerCSRFResult = registerCSRFFuture.join();

            haveSuccededAllServices = pushAttemptResult && registerCSRFResult;

            var message =
                    ObjectLeaftBuilder.builder()
                            .put("token", token)
                            .build();

            return new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK);

        } catch (RuntimeException e) {
            LOG.severe("Error generating CSRF token: " + e.getMessage());
            var message =
                    ObjectLeaftBuilder.builder()
                            .put("message", "There is an unexcpected error")
                            .build();
            return new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    public boolean isHaveSuccededAllServices() {
        return haveSuccededAllServices;
    }

}
