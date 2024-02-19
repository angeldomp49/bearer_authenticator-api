package org.makechtec.web.authentication_gateway.http.config;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServiceProvider {

    @Bean
    public BearerAuthenticationFactory bearerAuthenticationFactory() {
        return new BearerAuthenticationFactory(connectionInformation());
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
    public AuthenticationConnectionInformation authenticationConnectionInformation(){
        return new AuthenticationConnectionInformation();
    }

}
