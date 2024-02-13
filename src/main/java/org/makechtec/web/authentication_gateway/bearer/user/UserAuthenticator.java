package org.makechtec.web.authentication_gateway.bearer.user;

import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;

public class UserAuthenticator {

    private final UserProvider userProvider = new UserProvider();

    public boolean areValidCredentials(String username, String password){
        var user = userProvider.byUsername(username);

        if(user.isEmpty()){
            return false;
        }

        var hashedPassword =
                Hashing.sha256()
                        .hashString(password, StandardCharsets.UTF_8)
                        .toString();

        return user.get().hashedPassword().equals(hashedPassword);
    }



}
