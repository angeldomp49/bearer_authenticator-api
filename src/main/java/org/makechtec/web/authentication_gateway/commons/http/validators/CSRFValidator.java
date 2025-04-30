package org.makechtec.web.authentication_gateway.commons.http.validators;

public interface CSRFValidator {

    boolean isValidCSRF(String csrf, String secretKey) throws ControllerValidationException;

    String generateCSRFToken(String secretKey) throws ControllerValidationException;

}
