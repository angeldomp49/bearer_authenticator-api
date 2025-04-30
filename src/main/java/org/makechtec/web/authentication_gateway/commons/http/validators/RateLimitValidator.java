package org.makechtec.web.authentication_gateway.commons.http.validators;

import java.util.Map;

public interface RateLimitValidator {

    boolean hasAttemptsAvailable(Map<String, String> filters, String rateLimitDefinitionName) throws ControllerValidationException;

    void sumOneAttempt(Map<String, String> filters, String rateLimitDefinitionName) throws ControllerValidationException;

}
