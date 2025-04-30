package org.makechtec.web.authentication_gateway.resources.client.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasher;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.makechtec.web.authentication_gateway.resources.client.api.ClientDBConnection;
import org.makechtec.web.authentication_gateway.resources.client.api.ClientModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.util.HashMap;

@RestController
@RequestMapping("client/api")
public class ClientAPIResourceController {

    public static final String RATE_LIMIT_DEFINITION_NAME = "client-api-controller";
    private final PasswordHasher passwordHasher;
    private final SaltGenerator saltGenerator;
    private final HttpServletRequest request;
    private final ClientDBConnection clientDBConnection;
    private final ControllerValidatorFactory validatorFactory;
    private final CacheSystemTable cacheSystemTable;

    @Autowired
    public ClientAPIResourceController(PasswordHasher passwordHasher, SaltGenerator saltGenerator, HttpServletRequest request, ClientDBConnection clientDBConnection, ControllerValidatorFactory validatorFactory, CacheSystemTable cacheSystemTable) {
        this.passwordHasher = passwordHasher;
        this.saltGenerator = saltGenerator;
        this.request = request;
        this.clientDBConnection = clientDBConnection;
        this.validatorFactory = validatorFactory;
        this.cacheSystemTable = cacheSystemTable;
    }


    @PostMapping
    public ResponseEntity<String> store(
            @RequestHeader("Client-Agent") String clientAgent,
            @RequestHeader("Client-Address") String clientIP,
            @RequestHeader("Client-X-Csrf-Token") String applicationXCsrfToken,
            @RequestHeader("Client-Authorization") String clientAuthorization,
            @RequestHeader("Application-Authorization") String applicationAuthorization,

            @RequestParam("username") String username,
            @RequestParam("email") String email,
            @RequestParam("password") String password
    ) {
        var applicationIP = request.getRemoteAddr();

        var applicationToken = applicationAuthorization.replace("Bearer ", "").trim();
        var token = clientAuthorization.replace("Bearer ", "").trim();

        try {

            var rateLimitInformation = new HashMap<String, String>();
            rateLimitInformation.put("applicationIP", applicationIP);
            rateLimitInformation.put("clientIP", clientIP);
            rateLimitInformation.put("clientAgent", clientAgent);

            if (!validatorFactory.getSessionAuthenticator().isValidJWTSignature(applicationToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            if (!validatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME)) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            validatorFactory.getRateLimitValidator().sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);

            var secretKey = cacheSystemTable.request("temporaryApplicationSecretKey");

            if (!validatorFactory.getCSRFValidator().isValidCSRF(applicationXCsrfToken, secretKey)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            if (!validatorFactory.getSessionAuthenticator().isValidJWTSignature(token)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var salt = saltGenerator.generate();

            var rawHashed = passwordHasher.rawHashNotIncludingSalt(password, salt);

            clientDBConnection.store(new ClientModel(
                    username,
                    email,
                    rawHashed,
                    salt
            ));

            return new ResponseEntity<>(HttpStatus.CREATED);

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }


}
