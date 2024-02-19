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
        return new ConnectionInformation(
                "atepoztli__authentication_service__user",
                "4e?7Ca-]4>k9~d_=@r?6",
                "159.65.190.139",
                "5433",
                "tomcat_dev_database"
        );
    }

}
