package org.makechtec.web.authentication_gateway.app.dependency_injection;

import org.junit.jupiter.api.Test;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support_testing.connection_pool.ConnectionPoolMock;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.sql.ResultSet;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

@SpringBootTest
class ServiceProviderTest {

    @Autowired
    private ControllerValidatorFactory controllerValidatorFactory;

    @Test
    void getService() {


        assertNotNull(controllerValidatorFactory.getRateLimitValidator());
        assertNotNull(controllerValidatorFactory.getCSRFValidator());
        assertNotNull(controllerValidatorFactory.getIPBlackListValidator());
        assertNotNull(controllerValidatorFactory.getSessionAuthenticator());

        System.out.println("Successful loaded the test context");
    }

    @TestConfiguration
    public static class MockFactory {

        @Bean
        public ConnectionPool connectionPool() {
            final var connectionPool = new ConnectionPoolMock();
            connectionPool.setResultSetMock(mock(ResultSet.class));
            return connectionPool;
        }

    }

}