package org.makechtec.web.authentication_gateway.commons.http.validators;

public interface ControllerValidatorFactory {

    RateLimitValidator getRateLimitValidator();

    ResourceSessionValidator getSessionAuthenticator();

    CSRFValidator getCSRFValidator();

    IPBlackListValidator getIPBlackListValidator();

}
