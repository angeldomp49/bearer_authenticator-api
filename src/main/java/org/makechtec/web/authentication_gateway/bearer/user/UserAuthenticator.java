package org.makechtec.web.authentication_gateway.bearer.user;

import com.google.common.hash.Hashing;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

public class UserAuthenticator {

    private final UserProvider userProvider;
    private final PasswordHasher passwordHasher;

    public UserAuthenticator(UserProvider userProvider, PasswordHasher passwordHasher) {
        this.userProvider = userProvider;
        this.passwordHasher = passwordHasher;
    }

    public boolean areValidCredentials(String username, String password) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        var user = userProvider.byUsername(username);

        return user.filter(value -> passwordHasher.matches(password, value.hashedPassword()))
                .isPresent();

    }


}
