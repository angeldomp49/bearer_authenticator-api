package org.makechtec.web.authentication_gateway.csrf;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class ClientValidator {

    private static final Logger LOG = Logger.getLogger(ClientValidator.class.getName());

    private final ConnectionPool connectionPool;

    public ClientValidator(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }


    public boolean isAllowedClient(String ip) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            return
                    new WithPoolEngine<Boolean>(connectionPool)
                            .isPrepared()
                            .queryString("""
                                    SELECT COUNT(*) AS result
                                    FROM atepoztli__authentication_service__schema.allowed_clients
                                    WHERE ip = ?;
                                    """)
                            .addParamAtPosition(1, ip, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getInt("result") > 0;
                            });

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting csrf token information from database");
            throw e;
        }
    }

}
