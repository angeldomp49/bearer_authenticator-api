package org.makechtec.web.authentication_gateway.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.SQLException;
import java.util.Calendar;
import java.util.Objects;
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

    public CSRFController(ClientValidator clientValidator, CSRFTokenHandler csrfTokenHandler, HttpServletRequest request, CommonResponseBuilder responseBuilder, RateLimiter rateLimiter) {
        this.clientValidator = clientValidator;
        this.csrfTokenHandler = csrfTokenHandler;
        this.request = request;
        this.responseBuilder = responseBuilder;
        this.rateLimiter = rateLimiter;
    }

    @PostMapping("/client/public")
    public ResponseEntity<String> generateCSRFTokenForClient(
            @RequestHeader(name = "User-Address", required = false) String userAddress,
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("Client-Address") String clientAddress
    ) {

        var userIP = (Objects.isNull(userAddress)) ? request.getRemoteAddr() : userAddress;

        try {

            if(!this.rateLimiter.hasAttemptsThisClient(userIP, userAgent, clientAddress, "csrf")){
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            if (!this.clientValidator.isAllowedClient(clientAddress)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var expirationDate = Calendar.getInstance();

            expirationDate.add(Calendar.MINUTE, 30);

            var token = this.csrfTokenHandler.registerCSRFToken(userIP, userAgent, clientAddress, expirationDate.getTimeInMillis());

            var message =
                    ObjectLeaftBuilder.builder()
                            .put("token", token)
                            .build();

            return new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK);

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error generating CSRF token: " + e.getMessage());
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


}
