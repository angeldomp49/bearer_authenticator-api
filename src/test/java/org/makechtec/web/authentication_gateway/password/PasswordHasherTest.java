package org.makechtec.web.authentication_gateway.password;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class PasswordHasherTest {

    private final PasswordHasherNative passwordHasher;
    private final SaltGenerator saltGenerator = new SaltGenerator();

    @Autowired
    PasswordHasherTest(PasswordHasherNative passwordHasher) {
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