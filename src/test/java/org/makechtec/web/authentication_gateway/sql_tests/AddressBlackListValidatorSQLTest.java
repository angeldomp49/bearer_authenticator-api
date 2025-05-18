package org.makechtec.web.authentication_gateway.sql_tests;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.connection_pool.mysql.MySQLPooledConnectionCreator;
import org.makechtec.software.sql_support.connection_pool.postgres.PostgresPooledConnectionCreator;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class AddressBlackListValidatorSQLTest {

    private static ConnectionPool connectionPool;

    @BeforeAll
    static void setUp() throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        connectionPool = new ConnectionPool(1, SQLConfiguration.POSTGRES_POOLED_CONNECTION_CREATOR);

        connectionPool.boot();
    }
    
    @Test
    public void isAllowedClient() throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        
        var result = new WithPoolEngine<Short>(connectionPool)
                .queryString("""
                SELECT COUNT(*) AS result
                FROM atepoztli__authentication_service__schema.black_list__allowed_clients
                WHERE ip = ?;
                """)
                .isPrepared()
                .addParamAtPosition(1, "127.0.0.1", ParamType.TYPE_STRING)
                .run( resultSet -> {
                    
                    resultSet.next();
                    
                    return resultSet.getShort(1);
                    
                } );
        
        assertTrue(result > 0);
        
    }
    
}
