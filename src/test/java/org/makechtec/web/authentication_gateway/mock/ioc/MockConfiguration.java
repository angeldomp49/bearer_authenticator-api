package org.makechtec.web.authentication_gateway.mock.ioc;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.PooledConnection;
import org.mockito.Mockito;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.sql.Connection;
import java.sql.SQLException;

@TestConfiguration
public class MockConfiguration {

    @Bean
    public ConnectionPool connectionPool() {
        var pool = new ConnectionPool(Runtime.getRuntime().availableProcessors(), () -> new PooledConnection() {

            @Override
            public boolean isUsable() {
                return true;
            }

            @Override
            public Connection nativeConnection() {
                return Mockito.mock(Connection.class);
            }

            @Override
            public void close() throws SQLException {
            }
        });

        try {
            pool.boot();
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        return pool;
    }

}
