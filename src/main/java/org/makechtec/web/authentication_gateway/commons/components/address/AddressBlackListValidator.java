package org.makechtec.web.authentication_gateway.commons.components.address;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.IPBlackListValidator;

import java.sql.SQLException;
import java.util.logging.Logger;

public class AddressBlackListValidator implements IPBlackListValidator {

    private static final Logger LOG = Logger.getLogger(AddressBlackListValidator.class.getName());

    private final ConnectionPool connectionPool;

    public AddressBlackListValidator(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    @Override
    public boolean isValidIP(String ip) {
        return isValidIP(ip, "", """
                SELECT COUNT(*) AS result
                FROM atepoztli__authentication_service__schema.allowed_clients
                WHERE ip = ?;
                """);
    }

    @Override
    public boolean isValidIP(String ip, String tag) {
        return isValidIP(ip, tag, """
                SELECT COUNT(*) AS result
                FROM atepoztli__authentication_service__schema.allowed_clients
                WHERE ip = ?
                AND tag = ?;
                """);
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
