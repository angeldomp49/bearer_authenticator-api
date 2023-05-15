package org.makechtec.web.auth_api.config;

import org.makechtec.software.caltentli.hashing.HashStrategy;
import org.makechtec.software.caltentli.provider.SessionProvider;
import org.makechtec.software.caltentli.provider.UserProvider;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.user_session_handler.hashing.SHAMask;
import org.makechtec.software.user_session_handler.mapping.DBSessionMapper;
import org.makechtec.software.user_session_handler.mapping.DBUserMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServiceProvider {

    @Bean
    public UserProvider userProvider(){
        return new DBUserMapper(this.connectionInformation());
    }

    @Bean
    public SessionProvider sessionProvider(){
        return new DBSessionMapper(this.connectionInformation());
    }

    @Bean
    public HashStrategy hashStrategy(){
        return new SHAMask();
    }

    @Bean
    public ConnectionInformation connectionInformation(){
        return new ConnectionInformation(
                "makech",
                "3nitrotoluenO@",
                "localhost",
                "3306",
                "auth"
        );
    }


}
