package org.makechtec.web.authentication_gateway.password;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.makechtec.web.authentication_gateway.plugins.admin.api.user.UserDBConnection;
import org.makechtec.web.authentication_gateway.plugins.bearer.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.plugins.bearer.password.SaltGenerator;
import org.makechtec.web.authentication_gateway.plugins.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class PasswordHasherTest {

    private final PasswordHasher passwordHasher;
    private final SaltGenerator saltGenerator = new SaltGenerator();

    @MockBean
    private UserDBConnection userDBConnectionMock;
    @MockBean
    private RateLimiter rateLimiterMock;

    @Autowired
    PasswordHasherTest(PasswordHasher passwordHasher) {
        this.passwordHasher = passwordHasher;
    }

    @Test
    void matches() {
        var salt = saltGenerator.generate();
        var result1 = new String(Hex.encode(passwordHasher.rawHash("hello", salt)));

        var matches = passwordHasher.matches("hello", result1);
        assertTrue(matches);
    }
}