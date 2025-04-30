package org.makechtec.web.authentication_gateway.commons.http.validators;

public interface CSRFValidator {

    boolean nonValidCSRF(String csrf, String secretKey);
    
    boolean isValidCSRF(String csrf, String secretKey) throws ControllerValidationException;

    String generateCSRFToken(String secretKey) throws ControllerValidationException;

}
