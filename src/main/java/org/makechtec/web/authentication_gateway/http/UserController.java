package org.makechtec.web.authentication_gateway.http;

import org.makechtec.web.authentication_gateway.api.user.StoredUserModel;
import org.makechtec.web.authentication_gateway.api.user.UserDBConnection;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.password.SaltGenerator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;

@RestController
@RequestMapping("user")
public class UserController {

    private final UserDBConnection userDBConnection;
    private final PasswordHasher passwordHasher;
    private final SaltGenerator saltGenerator = new SaltGenerator();

    private final BearerAuthenticationFactory bearerAuthenticationFactory;

    public UserController(@Qualifier("userDBConnection") UserDBConnection userDBConnection, PasswordHasher passwordHasher, @Qualifier("bearerAuthenticationFactory") BearerAuthenticationFactory bearerAuthenticationFactory) {
        this.userDBConnection = userDBConnection;
        this.passwordHasher = passwordHasher;
        this.bearerAuthenticationFactory = bearerAuthenticationFactory;
    }

    @PostMapping
    public ResponseEntity<Void> store(
            @RequestHeader("Authorization") String authorization,

            @RequestParam("username") String username,
            @RequestParam("email") String email,
            @RequestParam("password") String password
    ) {

        var token = authorization.replace("Bearer ", "").trim();
        try {

            if (
                    bearerAuthenticationFactory.jwtTokenHandler().isInBlackList(token) ||
                            (!bearerAuthenticationFactory.jwtTokenHandler().isValidSignature(token))
            ) {
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var salt = saltGenerator.generate();
            userDBConnection.store(new StoredUserModel(
                    username,
                    email,
                    passwordHasher.hash(password),
                    salt
            ));

            return new ResponseEntity<>(HttpStatus.CREATED);
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

}
