package org.makechtec.web.authentication_gateway.commons.components.csrf;

import org.makechtec.bearer_authentication.tools.bearer.stateless.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.commons.http.validators.CSRFValidator;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;

public class CommonHeaderCSRFValidator implements CSRFValidator {

    private final CSRFTokenGenerator csrfTokenGenerator;

    public CommonHeaderCSRFValidator(CSRFTokenGenerator csrfTokenGenerator) {
        this.csrfTokenGenerator = csrfTokenGenerator;
    }

    @Override
    public boolean isValidCSRF(String csrf) throws ControllerValidationException {
        return csrfTokenGenerator.isValidCSRFToken(csrf);
    }

    @Override
    public String generateCSRFToken() throws ControllerValidationException {
        return csrfTokenGenerator.generateCSRFToken();
    }
}
