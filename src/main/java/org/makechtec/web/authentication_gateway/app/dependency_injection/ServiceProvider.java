package org.makechtec.web.authentication_gateway.app.dependency_injection;

import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.ArgonSettings;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasher;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SignaturePrinter;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.web.authentication_gateway.app.properties.AuthenticationConnectionInformation;
import org.makechtec.web.authentication_gateway.app.properties.CrypographyInformation;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.validation.rate_limit.RateLimitRegistry;
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
        return new PasswordHasherNative(new ArgonSettings(
                crypographyInformation().getArgon2SettingsMemory(),
                crypographyInformation().getArgon2SettingsIterations()
        ));
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
    public RateLimitRegistry rateLimiter() {
        return new RateLimitRegistry(this.connectionInformation());
    }

    @Bean
    public CommonResponseBuilder commonResponseBuilder() {
        return new CommonResponseBuilder();
    }
}
