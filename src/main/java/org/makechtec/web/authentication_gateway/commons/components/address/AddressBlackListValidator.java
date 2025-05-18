package org.makechtec.web.authentication_gateway.commons.components.address;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.IPBlackListValidator;

import java.sql.SQLException;
import java.util.logging.Logger;

public class AddressBlackListValidator implements IPBlackListValidator {

    private static final String SCHEMA_NAME = "atepoztli__authentication_service__schema";
    private static final String ALLOWED_CLIENTS_TABLE = "black_list__allowed_clients";
    private static final String FORBIDDEN_CLIENTS_TABLE = "black_list__allowed_clients";

    private static final Logger LOG = Logger.getLogger(AddressBlackListValidator.class.getName());

    private final ConnectionPool connectionPool;

    public AddressBlackListValidator(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    @Override
    public boolean isValidIP(String ip) {
        return isValidIP(ip, "", String.format("""
                SELECT COUNT(*) AS result
                FROM %s.%s
                WHERE ip = ?;
                """, SCHEMA_NAME, ALLOWED_CLIENTS_TABLE));
    }

    @Override
    public boolean isValidIP(String ip, String tag) {
        return isValidIP(ip, tag, String.format("""
                SELECT COUNT(*) AS result
                FROM %s.%s
                WHERE ip = ?
                AND tag = ?;
                """, SCHEMA_NAME, ALLOWED_CLIENTS_TABLE));
    }

    @Override
    public boolean isForbiddenIP(String ip, String tag) throws ControllerValidationException {
        try {
            return
                    new WithPoolEngine<Boolean>(connectionPool)
                            .isPrepared()
                            .queryString(String.format("""
                                    SELECT COUNT(*) AS result
                                    FROM %s.%s
                                    WHERE ip = ?
                                    AND tag = ?;
                                    """, SCHEMA_NAME, FORBIDDEN_CLIENTS_TABLE))
                            .addParamAtPosition(1, ip, ParamType.TYPE_STRING)
                            .addParamAtPosition(2, tag, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getInt("result") > 0;
                            });

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting csrf token information from database");
            throw new ControllerValidationException(e.getMessage());
        }
    }

    private boolean isValidIP(String ip, String tag, String queryString) throws ControllerValidationException {
        try {
            return
                    new WithPoolEngine<Boolean>(connectionPool)
                            .isPrepared()
                            .queryString(queryString)
                            .addParamAtPosition(1, ip, ParamType.TYPE_STRING)
                            .addParamAtPosition(2, tag, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getInt("result") > 0;
                            });

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting csrf token information from database");
            throw new ControllerValidationException(e.getMessage());
        }
    }


}
