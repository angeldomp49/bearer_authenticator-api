package org.makechtec.web.authentication_gateway.commons.http.validators;

public interface CSRFValidator {

    boolean isValidCSRF(String csrf) throws ControllerValidationException;

    String generateCSRFToken() throws ControllerValidationException;

}
