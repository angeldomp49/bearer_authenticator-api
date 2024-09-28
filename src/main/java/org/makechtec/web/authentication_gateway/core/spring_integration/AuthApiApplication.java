package org.makechtec.web.authentication_gateway.core.spring_integration;

import org.makechtec.web.authentication_gateway.core.bootstrap.AuthenticationGatewayApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthApiApplication {

    public static AuthenticationGatewayApplication application;

    public static void main(String[] args) {

        var app = new AuthenticationGatewayApplication();

        app.boot(args);

        application = app;

        SpringApplication.run(AuthApiApplication.class, args);
    }

}
