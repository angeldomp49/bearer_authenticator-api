package org.makechtec.web.authentication_gateway.commons.components.csrf;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.makechtec.bearer_authentication.tools.bearer.stateless.csrf.CSRFTokenGenerator;

import static org.junit.jupiter.api.Assertions.*;

class CommonHeaderCSRFValidatorTest {
    
    private CommonHeaderCSRFValidator validator;
    
    @BeforeEach
    void setUp() {
        validator = new CommonHeaderCSRFValidator(
                new CSRFTokenGenerator()
        );
    }

    @Test
    void generateCSRFToken() {
        
        final var secretKey = "secretKey";
        
        final var result = validator.generateCSRFToken(secretKey);
        
        assertTrue(validator.isValidCSRF(result, secretKey));
        
        final var anotherSecretKey = "anotherSecretKey";
        
        assertTrue(validator.nonValidCSRF(result, anotherSecretKey));
    }
}