package org.makechtec.web.auth_api.config;

import org.makechtec.software.caltentli.hashing.HashStrategy;
import org.makechtec.software.caltentli.provider.SessionProvider;
import org.makechtec.software.caltentli.provider.UserProvider;
import org.makechtec.software.caltentli_mock.in_memory.InMemorySessionProvider;
import org.makechtec.software.caltentli_mock.in_memory.InMemoryUserProvider;
import org.makechtec.software.caltentli_mock.sha.SHAHash;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServiceProvider {

    @Bean
    public UserProvider userProvider(){
        return new InMemoryUserProvider();
    }

    @Bean
    public SessionProvider sessionProvider(){
        return new InMemorySessionProvider();
    }

    @Bean
    public HashStrategy hashStrategy(){
        return new SHAHash();
    }


}
