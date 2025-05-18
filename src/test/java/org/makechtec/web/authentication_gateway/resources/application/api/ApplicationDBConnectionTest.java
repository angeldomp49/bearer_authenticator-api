package org.makechtec.web.authentication_gateway.resources.application.api;

import org.junit.jupiter.api.Test;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class ApplicationDBConnectionTest {
    
    @Autowired
    private ApplicationDBConnection db;
    
    @Autowired
    private SaltGenerator saltGenerator;
    
    @Autowired
    private PasswordHasherNative passwordHasher;

    @Test
    void store() throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        var salt = saltGenerator.generate();

        var accessKey = "110333642a";
        var secret = "Hello World!";

        var rawHashed = passwordHasher.rawHashNotIncludingSalt(secret, salt);
        
        db.store(new ApplicationModel(
                accessKey,
                rawHashed,
                salt
        ));
        
    }
    
    
}