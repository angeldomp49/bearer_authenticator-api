package org.makechtec.web.auth_api.rest;

import org.makechtec.software.caltentli.auth.AuthResponse;
import org.makechtec.software.caltentli.hashing.HashStrategy;
import org.makechtec.software.caltentli.provider.Session;
import org.makechtec.software.caltentli.provider.SessionProvider;
import org.makechtec.software.caltentli.provider.UserProvider;
import org.makechtec.software.caltentli.user_auth.UserAuthRequest;
import org.makechtec.software.caltentli.user_auth.UserAuthenticator;
import org.makechtec.software.user_session_handler.session_handling.UserSessionHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserProvider userProvider;
    private final SessionProvider sessionProvider;
    private final HashStrategy hashStrategy;


    @Autowired
    public AuthController(UserProvider userProvider, SessionProvider sessionProvider, HashStrategy hashStrategy) {
        this.userProvider = userProvider;
        this.sessionProvider = sessionProvider;
        this.hashStrategy = hashStrategy;
    }

    @PostMapping("/login/user")
    @ResponseStatus(HttpStatus.CREATED)
    public LoggedResponse loginByUserRequest(@ModelAttribute("userRequest") UserRequest userRequest){

        var auth = this.createUserAuthenticator();

        auth.loadUserRequest(new UserAuthRequest(userRequest.username(), userRequest.password()));
        var response = auth.login();
        return new LoggedResponse(response.isLoggedIn(), response.message(), auth.getGeneratedToken());

    }

    @PostMapping("/login/token")
    @ResponseStatus(HttpStatus.CREATED)
    public AuthResponse loginByToken(@RequestParam("token") String token){

        var auth = this.createUserAuthenticator();

        auth.loadToken(token);
        return auth.check();

    }

    @DeleteMapping("/logout")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@RequestParam("token") String token){

        var auth = this.createUserAuthenticator();

        auth.loadToken(token);
        auth.logout();

    }

    @GetMapping("/session-info")
    @ResponseStatus(HttpStatus.OK)
    public Session sessionInfoByToken(@RequestParam("token") String token){
        return this.sessionProvider.byToken(token).get();
    }

    private UserAuthenticator createUserAuthenticator(){
        return new UserSessionHandler(this.userProvider, this.sessionProvider, this.hashStrategy);
    }

}
