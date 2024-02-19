package org.makechtec.web.authentication_gateway.bearer.user;

import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;
import java.sql.SQLException;

public class UserAuthenticator {

    private final UserProvider userProvider;

    public UserAuthenticator(UserProvider userProvider) {
        this.userProvider = userProvider;
    }

    public boolean areValidCredentials(String username, String password) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        var user = userProvider.byUsername(username);

        if (user.isEmpty()) {
            return false;
        }

        var hashedPassword =
                Hashing.sha256()
                        .hashString(password, StandardCharsets.UTF_8)
                        .toString();

        return user.get().hashedPassword().equals(hashedPassword);
    }


}
