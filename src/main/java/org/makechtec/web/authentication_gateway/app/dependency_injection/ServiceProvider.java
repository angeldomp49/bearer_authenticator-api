package org.makechtec.web.authentication_gateway.app.dependency_injection;

import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.ArgonSettings;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.csrf.CSRFTokenGenerator;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.postgres.PostgresPooledConnectionCreator;
import org.makechtec.web.authentication_gateway.app.properties.AuthenticationConnectionInformation;
import org.makechtec.web.authentication_gateway.app.properties.CrypographyInformation;
import org.makechtec.web.authentication_gateway.commons.components.address.AddressBlackListValidator;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.components.csrf.CommonHeaderCSRFValidator;
import org.makechtec.web.authentication_gateway.commons.components.random_string.RandomStringGenerator;
import org.makechtec.web.authentication_gateway.commons.components.rate_limit.CommonRateLimitValidator;
import org.makechtec.web.authentication_gateway.commons.components.rate_limit.RateLimitRegistry;
import org.makechtec.web.authentication_gateway.commons.components.session.CommonSessionValidator;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.validators.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServiceProvider {

    @Bean
    public ControllerValidatorFactory controllerValidatorFactory() {
        return new ControllerValidatorFactory() {
            @Override
            public RateLimitValidator getRateLimitValidator() {
                return new CommonRateLimitValidator(
                        connectionPool(),
                        rateLimiter()
                );
            }

            @Override
            public ResourceSessionValidator getSessionAuthenticator() {
                return new CommonSessionValidator(
                        connectionPool(),
                        passwordHasherNative(),
                        new JWTTokenGenerator()
                );
            }

            @Override
            public CSRFValidator getCSRFValidator() {
                return new CommonHeaderCSRFValidator(
                        new CSRFTokenGenerator()
                );
            }

            @Override
            public IPBlackListValidator getIPBlackListValidator() {
                return new AddressBlackListValidator(
                        connectionPool()
                );
            }
        };
    }
    
    @Bean
    public CacheSystemTable cacheSystemTable() {
        return new CacheSystemTable();
    }
    
    @Bean
    public RandomStringGenerator randomStringGenerator() {
        return new RandomStringGenerator();
    }

    @Bean
    public PasswordHasherNative passwordHasherNative() {
        return new PasswordHasherNative(new ArgonSettings(
                65000,
                1000
        ));
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
    public AuthenticationConnectionInformation authenticationConnectionInformation() {
        return new AuthenticationConnectionInformation();
    }

    @Bean
    public CrypographyInformation crypographyInformation() {
        return new CrypographyInformation();
    }

    @Bean
    public RateLimitRegistry rateLimiter() {
        return new RateLimitRegistry(this.connectionPool());
    }

    @Bean
    public ConnectionPool connectionPool() {
        return new ConnectionPool(
                8,
                new PostgresPooledConnectionCreator(
                        connectionInformation()
                )
        );
    }

    @Bean
    public CommonJSONResponseBuilder commonResponseBuilder() {
        return new CommonJSONResponseBuilder();
    }
}
