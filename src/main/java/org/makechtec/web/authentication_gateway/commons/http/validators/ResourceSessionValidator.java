package org.makechtec.web.authentication_gateway.commons.http.validators;

import org.makechtec.web.authentication_gateway.commons.components.session.AuthenticatedResourceSession;

public interface ResourceSessionValidator {

    boolean areValidCredentials(String accessKey, String secret, String resourceKind) throws ControllerValidationException;

    AuthenticatedResourceSession createSession(String resourceId) throws ControllerValidationException;

    String createJWT(AuthenticatedResourceSession sessionInformation) throws ControllerValidationException;

    boolean isValidJWTSignature(String token) throws ControllerValidationException;

}
