package org.makechtec.web.authentication_gateway.commons.http.validators;

public interface IPBlackListValidator {

    boolean isValidIP(String ip) throws ControllerValidationException;

    boolean isValidIP(String ip, String tag) throws ControllerValidationException;

    boolean isForbiddenIP(String ip, String tag) throws ControllerValidationException;
}
