package org.makechtec.web.authentication_gateway.resources.application.api;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class ApplicationDBConnection {

    private static final Logger LOG = Logger.getLogger(ApplicationDBConnection.class.getName());

    private final ConnectionPool connectionPool;

    public ApplicationDBConnection(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    public void store(ApplicationModel applicationModel) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            new WithPoolEngine<Void>(connectionPool)
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.applications
                            (accessKey, hashed_password, salt)
                            VALUES(?,?,?)
                            """)
                    .addParamAtPosition(1, applicationModel.accessKey(), ParamType.TYPE_STRING)
                    .addParamAtPosition(2, applicationModel.hashedSecret(), ParamType.TYPE_BINARY_SINGLE)
                    .addParamAtPosition(3, applicationModel.salt(), ParamType.TYPE_BINARY_SINGLE)
                    .isPrepared()
                    .update();
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error storing application information: " + e.getMessage());
            throw e;
        }
    }

}
