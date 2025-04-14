package org.makechtec.web.authentication_gateway.resources.application.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.bearer_authentication.tools.bearer.stateless.csrf.CSRFTokenGenerator;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.resources.application.validation.ApplicationRateLimitValidator;
import org.makechtec.web.authentication_gateway.validation.address.AddressBlackListValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;

import java.sql.SQLException;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Logger;

@RequestMapping("application/csrf")
public class ApplicationCSRFController {

    private static final Logger LOG = Logger.getLogger(ApplicationCSRFController.class.getName());

    private final ApplicationRateLimitValidator rateLimitValidator;
    private final AddressBlackListValidator addressBlackListValidator;
    private final HttpServletRequest request;
    private final CommonResponseBuilder responseBuilder;
    private final CSRFTokenGenerator csrfTokenGenerator;

    public ApplicationCSRFController(ApplicationRateLimitValidator rateLimitValidator, AddressBlackListValidator addressBlackListValidator, HttpServletRequest request, CommonResponseBuilder responseBuilder, CSRFTokenGenerator csrfTokenGenerator) {
        this.addressBlackListValidator = addressBlackListValidator;
        this.rateLimitValidator = rateLimitValidator;
        this.request = request;
        this.responseBuilder = responseBuilder;
        this.csrfTokenGenerator = csrfTokenGenerator;
    }


    @GetMapping
    public ResponseEntity<String> getCSRF(
            @RequestHeader("User-Agent") String userAgent
    ) {
        var userIP = request.getRemoteAddr();


        try {

            CompletableFuture<Boolean> rateLimitFuture = CompletableFuture.supplyAsync(() -> {
                try {
                    return this.rateLimitValidator.hasAttemptsThisClient(userIP, userAgent, "csrf");
                } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                    return false;
                }
            });

            CompletableFuture<String> tokenFuture = CompletableFuture.supplyAsync(this.csrfTokenGenerator::generateCSRFToken);


            var isAllowed = this.addressBlackListValidator.isAllowedClient(userIP);

            if (!isAllowed) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            if (!rateLimitFuture.join()) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            var token = tokenFuture.join();

            CompletableFuture.supplyAsync(() -> {
                try {
                    this.rateLimitValidator.pushAttemptToThisClient(userIP, userAgent);
                    return null;
                } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
                    LOG.severe("Error pushing attempt for client: " + e.getMessage());
                    return null;
                }
            });

            var message =
                    ObjectLeafBuilder.builder()
                            .put("token", token)
                            .build();

            return new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK);

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error generating CSRF token: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }


    }

}
