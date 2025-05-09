package org.makechtec.web.authentication_gateway.commons.components.rate_limit;

import org.junit.jupiter.api.Test;
import org.makechtec.software.sql_support_testing.connection_pool.ConnectionPoolMock;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

class RateLimitRegistryTest {

    @Test
    void registerNewRateLimit() throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        final var connectionPool = new ConnectionPoolMock();

        connectionPool.setResultSetMock(mock(ResultSet.class));

        final RateLimitRegistry rateLimitRegistry = new RateLimitRegistry(connectionPool);

        rateLimitRegistry.registerNewRateLimit(
                new RateLimitSchema(
                        """
                                {
                                    "fields":[]
                                }
                                """,
                        new RateLimit(
                                "",
                                1,
                                RateLimitTimeUnit.MINUTE.getName(),
                                10
                        )
                )
        );

    }

    @Test
    void registerNewRateLimitException() throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        final var connectionPool = new ConnectionPoolMock();

        connectionPool.setExceptionToForce(mock(SQLException.class));

        final RateLimitRegistry rateLimitRegistry = new RateLimitRegistry(connectionPool);

        assertThrows(SQLException.class, () ->

                rateLimitRegistry.registerNewRateLimit(
                        new RateLimitSchema(
                                """
                                        {
                                            "fields":[]
                                        }
                                        """,
                                new RateLimit(
                                        "",
                                        1,
                                        RateLimitTimeUnit.MINUTE.getName(),
                                        10
                                )
                        )
                )
        );

    }

}