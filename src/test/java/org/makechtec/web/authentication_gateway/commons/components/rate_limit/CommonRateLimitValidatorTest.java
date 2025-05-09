package org.makechtec.web.authentication_gateway.commons.components.rate_limit;

import org.junit.jupiter.api.Test;
import org.makechtec.software.sql_support_testing.connection_pool.ConnectionPoolMock;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CommonRateLimitValidatorTest {

    @Test
    void hasAttemptsAvailable() throws SQLException {

        final var resultsetMock = mock(ResultSet.class);

        when(resultsetMock.next()).thenReturn(true);

        when(resultsetMock.getString("schema"))
                .thenReturn("{}");

        when(resultsetMock.getString("title"))
                .thenReturn("client-rate-limit-schema");

        when(resultsetMock.getInt("attempts"))
                .thenReturn(1000);

        when(resultsetMock.getString("unit"))
                .thenReturn(RateLimitTimeUnit.DAY.getName());

        when(resultsetMock.getInt("time_quantity"))
                .thenReturn(2);

        when(resultsetMock.next()).thenReturn(true);

        when(resultsetMock.getInt("result"))
                .thenReturn(2);

        final var connectionPool = new ConnectionPoolMock();

        connectionPool.setResultSetMock(resultsetMock);

        final var connectionPoolNoMethods = new ConnectionPoolMock();

        final var rateLimitRegistry = new RateLimitRegistry(connectionPoolNoMethods);

        final var validator = new CommonRateLimitValidator(connectionPool, rateLimitRegistry);

        final var result = validator.hasAttemptsAvailable(new HashMap<>(), "client-rate-limit-schema");

        assertTrue(result);
    }

    @Test
    void hasAttemptsAvailableException() {


        final var connectionPool = new ConnectionPoolMock();

        connectionPool.setExceptionToForce(new SQLException());

        final var validator = new CommonRateLimitValidator(connectionPool, new RateLimitRegistry(connectionPool));

        assertThrows(ControllerValidationException.class, () -> validator.hasAttemptsAvailable(new HashMap<>(), "client-rate-limit-schema"));
    }

    @Test
    void sumOneAttempt() {
        final var connectionPool = new ConnectionPoolMock();

        connectionPool.setResultSetMock(mock(ResultSet.class));

        final var validator = new CommonRateLimitValidator(
                connectionPool,
                new RateLimitRegistry(connectionPool)
        );

        validator.sumOneAttempt(new HashMap<>(), "client-rate-limit-schema");
    }

    @Test
    void sumOneAttemptException() {
        final var connectionPool = new ConnectionPoolMock();

        connectionPool.setExceptionToForce(new SQLException());

        final var validator = new CommonRateLimitValidator(
                connectionPool,
                new RateLimitRegistry(connectionPool)
        );

        assertThrows(ControllerValidationException.class, () -> validator.sumOneAttempt(new HashMap<>(), "client-rate-limit-schema"));
    }

}