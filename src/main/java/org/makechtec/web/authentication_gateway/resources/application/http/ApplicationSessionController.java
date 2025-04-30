package org.makechtec.web.authentication_gateway.resources.application.http;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@RequestMapping("application/session")
@RestController
public class ApplicationSessionController {

    public static final String RATE_LIMIT_DEFINITION_NAME = "application-session-controller";
    public static final String RESOURCE_KIND = "application";
    private final ControllerValidatorFactory controllerValidatorFactory;
    private final HttpServletRequest request;
    private final CommonJSONResponseBuilder commonJSONResponseBuilder;
    private final CacheSystemTable cacheSystemTable;

    @Autowired
    public ApplicationSessionController(ControllerValidatorFactory controllerValidatorFactory, HttpServletRequest request, CommonJSONResponseBuilder commonJSONResponseBuilder, CacheSystemTable cacheSystemTable) {
        this.controllerValidatorFactory = controllerValidatorFactory;
        this.request = request;
        this.commonJSONResponseBuilder = commonJSONResponseBuilder;
        this.cacheSystemTable = cacheSystemTable;
    }


    @PostMapping("/login")
    public ResponseEntity<String> loginByUserRequest(
            @RequestHeader("Application-Agent") String applicationAgent,
            @RequestHeader("Application-X-Csrf-Token") String applicationXCsrfToken,

            @RequestParam("accessKey") String accessKey,
            @RequestParam("secret") String secret
    ) {

        var applicationIP = request.getRemoteAddr();

        try {

            var rateLimitInformation = new HashMap<String, String>();

            rateLimitInformation.put("applicationIP", applicationIP);
            rateLimitInformation.put("applicationAgent", applicationAgent);

            if (!controllerValidatorFactory.getRateLimitValidator().hasAttemptsAvailable(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME)) {
                return new ResponseEntity<>(HttpStatus.TOO_MANY_REQUESTS);
            }

            controllerValidatorFactory.getRateLimitValidator().sumOneAttempt(rateLimitInformation, RATE_LIMIT_DEFINITION_NAME);

            var secretKey = cacheSystemTable.request("temporaryApplicationSecretKey");
            if (!controllerValidatorFactory.getCSRFValidator().isValidCSRF(applicationXCsrfToken, secretKey)) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var areValidCredentials = controllerValidatorFactory.getSessionAuthenticator().areValidCredentials(accessKey, secret, RESOURCE_KIND);

            if (!areValidCredentials) {
                var message =
                        ObjectLeafBuilder.builder()
                                .put("message", "Username or password are invalid")
                                .build();

                return new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
            }

            var session = controllerValidatorFactory.getSessionAuthenticator().createSession(accessKey);
            var token = controllerValidatorFactory.getSessionAuthenticator().createJWT(session);

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
            @RequestHeader("Application-Authorization") String applicationAuthorization
    ) {
        var token = applicationAuthorization.replace("Bearer ", "").trim();


        boolean isValidToken = false;

        try {
            isValidToken = controllerValidatorFactory.getSessionAuthenticator().isValidJWTSignature(token);
        } catch (ControllerValidationException e) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        var message =
                ObjectLeafBuilder.builder()
                        .put("isValid", isValidToken)
                        .build();

        return isValidToken ? new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.OK), HttpStatus.OK) :
                new ResponseEntity<>(commonJSONResponseBuilder.createResponse(message, HttpStatus.UNAUTHORIZED), HttpStatus.UNAUTHORIZED);
    }

    @DeleteMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Application-Authorization") String applicationAuthorization) {

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

}
