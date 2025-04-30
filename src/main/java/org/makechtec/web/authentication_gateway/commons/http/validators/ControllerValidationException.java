package org.makechtec.web.authentication_gateway.commons.http.validators;

public class ControllerValidationException extends RuntimeException {
    public ControllerValidationException(String message) {
        super(message);
    }

    public ControllerValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
