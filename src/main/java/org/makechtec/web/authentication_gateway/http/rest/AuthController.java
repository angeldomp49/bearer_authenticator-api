package org.makechtec.web.authentication_gateway.http.rest;


import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final BearerAuthenticationFactory bearerAuthenticationFactory = new BearerAuthenticationFactory();
    private final List<String> blackList = new ArrayList<>();

    @PostMapping("/login")
    @ResponseStatus(HttpStatus.CREATED)
    public String loginByUserRequest(@RequestParam("username") String username, @RequestParam("password") String password) {


        var areValidCredentials = bearerAuthenticationFactory.userAuthenticator().areValidCredentials(username, password);

        if (!areValidCredentials) {
            return "error";
        }

        var session = bearerAuthenticationFactory.sessionGenerator().createForUser(username);

        return bearerAuthenticationFactory.jwtTokenHandler().createTokenForSession(session);

    }

    @GetMapping("/check")
    @ResponseStatus(HttpStatus.OK)
    public String checkToken(@RequestHeader("Authorization") String authorization) {
        var token = authorization.replace("Basic ", "").trim();
        var isValidToken = bearerAuthenticationFactory.jwtTokenHandler().isValidSignature(token);

        return "isValid: " + isValidToken;
    }

    @DeleteMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestHeader("Authorization") String authorization) {

        var token = authorization.replace("Basic ", "").trim();

        blackList.add(token);

    }


}
