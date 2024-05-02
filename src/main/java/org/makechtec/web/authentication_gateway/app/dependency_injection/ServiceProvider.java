package org.makechtec.web.authentication_gateway.app.dependency_injection;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.web.authentication_gateway.api.user.UserDBConnection;
import org.makechtec.web.authentication_gateway.app.properties.AuthenticationConnectionInformation;
import org.makechtec.web.authentication_gateway.app.properties.CrypographyInformation;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServiceProvider {

    @Bean
    public BearerAuthenticationFactory bearerAuthenticationFactory() {
        return new BearerAuthenticationFactory(
                connectionInformation(),
                new SignaturePrinter(this.crypographyInformation().getSecretKey()),
                passwordHasher());
    }

    @Bean
    public ConnectionInformation connectionInformation() {
        var authenticationConnectionInformation = this.authenticationConnectionInformation();
        return new ConnectionInformation(
                authenticationConnectionInformation.getUser(),
                authenticationConnectionInformation.getPassword(),
                authenticationConnectionInformation.getHostname(),
                authenticationConnectionInformation.getPort(),
                authenticationConnectionInformation.getDatabase()
        );
    }

    @Bean
    public PasswordHasher passwordHasher() {
        return new PasswordHasher(crypographyInformation());
    }

    @Bean
    public UserDBConnection userDBConnection() {
        return new UserDBConnection(connectionInformation());
    }

    @Bean
    public AuthenticationConnectionInformation authenticationConnectionInformation() {
        return new AuthenticationConnectionInformation();
    }

    @Bean
    public CrypographyInformation crypographyInformation() {
        return new CrypographyInformation();
    }

    @Bean
    public ClientValidator clientValidator() {
        return new ClientValidator(this.connectionInformation());
    }

    @Bean
    public CSRFTokenHandler csrfTokenHandler() {
        return new CSRFTokenHandler(
                this.connectionInformation(),
                new CSRFTokenGenerator(this.crypographyInformation().getSecretKey())
        );
    }

    @Bean
    public RateLimiter rateLimiter() {
        return new RateLimiter(this.connectionInformation());
    }

    @Bean
    public CommonResponseBuilder commonResponseBuilder() {
        return new CommonResponseBuilder();
    }
}
