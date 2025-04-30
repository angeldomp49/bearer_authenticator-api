package org.makechtec.web.authentication_gateway.resources.client.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.components.random_string.RandomStringGenerator;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@RequestMapping("client/session")
@RestController
public class ClientSessionController {

    public static final String RESOURCE_KIND = "client-kind";
    public static final String RATE_LIMIT_DEFINITION_NAME = "client-session-controller";
    private final HttpServletRequest request;
    private final CommonJSONResponseBuilder commonJSONResponseBuilder;
    private final ControllerValidatorFactory validatorFactory;
    private final CacheSystemTable cacheSystemTable;
    private final RandomStringGenerator randomStringGenerator;

    @Autowired
    public ClientSessionController(HttpServletRequest request, CommonJSONResponseBuilder commonJSONResponseBuilder, ControllerValidatorFactory validatorFactory, CacheSystemTable cacheSystemTable, RandomStringGenerator randomStringGenerator) {
        this.request = request;
        this.commonJSONResponseBuilder = commonJSONResponseBuilder;
        this.validatorFactory = validatorFactory;
        this.cacheSystemTable = cacheSystemTable;
        this.randomStringGenerator = randomStringGenerator;
    }


    @PostMapping("/login")
    public ResponseEntity<String> loginByUserRequest(
            @RequestHeader("Client-Address") String clientIP,
            @RequestHeader("Client-Agent") String clientAgent,
            @RequestHeader("Client-X-Csrf-Token") String clientXCsrfToken,

            @RequestHeader("Application-Authorization") String applicationAuthorization,
            @RequestHeader("Application-X-Csrf-Token") String applicationXCsrfToken,

            @RequestParam("username") String username,
            @RequestParam("password") String password
    ) {

        var applicationIP = request.getRemoteAddr();

        try {

            var applicationJWTToken = applicationAuthorization.replace("Bearer ", "");

            var rateLimitInformation = new HashMap<String, String>();
            rateLimitInformation.put("applicationIP", applicationIP);
            rateLimitInformation.put("clientIP", clientIP);
            rateLimitInformation.put("clientAgent", clientAgent);

            if (!validatorFactory.getSessionAuthenticator().isValidJWTSignature(applicationJWTToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            if (!validatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME)) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            validatorFactory.getRateLimitValidator().sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);

            if (validatorFactory.getCSRFValidator().nonValidCSRF(clientXCsrfToken, cacheSystemTable.request("temporaryApplicationSecretKey"))) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var areValidCredentials = validatorFactory.getSessionAuthenticator().areValidCredentials(username, password, RESOURCE_KIND);

            if (!areValidCredentials) {
                var message =
                        ObjectLeafBuilder.builder()
                                .put("message", "Username or password are invalid")
                                .build();

                return new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
            }

            var session = validatorFactory.getSessionAuthenticator().createSession(username);
            var token = validatorFactory.getSessionAuthenticator().createJWT(session);

            var message =
                    ObjectLeafBuilder.builder()
                            .put("token", token)
                            .build();

            return new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

        } catch (ControllerValidationException e) {
            var message =
                    ObjectLeafBuilder.builder()
                            .put("message", "There was an error in the application")
                            .build();

            return new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.INTERNAL_SERVER_ERROR), HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

    @GetMapping("/check")
    public ResponseEntity<String> checkToken(
            @RequestHeader("Application-Authorization") String applicationAuthorization,
            @RequestHeader("Client-Authorization") String clientAuthorization
    ) {

        var applicationToken = applicationAuthorization.replace("Bearer ", "").trim();
        var token = clientAuthorization.replace("Bearer ", "").trim();

        try {

            if (!validatorFactory.getSessionAuthenticator().isValidJWTSignature(applicationToken)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var isValidToken = validatorFactory.getSessionAuthenticator().isValidJWTSignature(token);

            var message =
                    ObjectLeafBuilder.builder()
                            .put("isValid", isValidToken)
                            .build();

            return isValidToken ? new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK) :
                    new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);

        } catch (ControllerValidationException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }

    }

}
