package org.makechtec.web.authentication_gateway.csrf;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.postgres.PostgresEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class ClientValidator {

    private static final Logger LOG = Logger.getLogger(ClientValidator.class.getName());

    private final ConnectionInformation connectionInformation;

    public ClientValidator(ConnectionInformation connectionInformation) {
        this.connectionInformation = connectionInformation;
    }

    public boolean isAllowedClient(String ip) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            return
                new PostgresEngine<Boolean>(connectionInformation)
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
