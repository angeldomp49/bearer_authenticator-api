package org.makechtec.web.authentication_gateway.password;

import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest
class PasswordHasherTest {

    private final PasswordHasher passwordHasher;
    private final SaltGenerator saltGenerator = new SaltGenerator();

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