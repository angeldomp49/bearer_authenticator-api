package org.makechtec.web.authentication_gateway.commons.components.address;

import org.junit.jupiter.api.Test;
import org.makechtec.software.sql_support_testing.connection_pool.ConnectionPoolMock;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;

import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AddressBlackListValidatorTest {

    @Test
    void isValidIP() throws SQLException {

        var resultSetMock = mock(ResultSet.class);

        when(resultSetMock.getInt(anyString()))
                .thenReturn(1);

        var connectionPool = new ConnectionPoolMock();

        connectionPool.setResultSetMock(resultSetMock);

        var addressBlackListValidator = new AddressBlackListValidator(connectionPool);

        var result = addressBlackListValidator.isValidIP("127.0.0.1");

        assertTrue(result);
    }

    @Test
    void testIsValidIP() throws SQLException {

        var resultSetMock = mock(ResultSet.class);

        when(resultSetMock.getInt(anyString()))
                .thenReturn(1);

        var connectionPool = new ConnectionPoolMock();

        connectionPool.setResultSetMock(resultSetMock);

        var addressBlackListValidator = new AddressBlackListValidator(connectionPool);

        var result = addressBlackListValidator.isValidIP("127.0.0.1", "tag");

        assertTrue(result);

    }


    @Test
    void testIsValidIPThrows() throws SQLException {

        var resultSetMock = mock(ResultSet.class);

        var connectionPool = new ConnectionPoolMock();

        connectionPool.setExceptionToForce(new SQLException());

        var addressBlackListValidator = new AddressBlackListValidator(connectionPool);

        assertThrows(ControllerValidationException.class, () -> addressBlackListValidator.isValidIP("127.0.0.1", "tag"));


    }

}