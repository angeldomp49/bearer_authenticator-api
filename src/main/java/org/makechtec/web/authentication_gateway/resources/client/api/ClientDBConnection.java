package org.makechtec.web.authentication_gateway.resources.client.api;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class ClientDBConnection {

    private static final Logger LOG = Logger.getLogger(ClientDBConnection.class.getName());

    private final ConnectionPool connectionPool;

    public ClientDBConnection(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    public void store(ClientModel clientModel) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            new WithPoolEngine<Void>(connectionPool)
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.clients
                            (username, email, password, salt)
                            VALUES(?,?,?,?)
                            """)
                    .addParamAtPosition(1, clientModel.username(), ParamType.TYPE_STRING)
                    .addParamAtPosition(2, clientModel.email(), ParamType.TYPE_STRING)
                    .addParamAtPosition(3, clientModel.hashedPassword(), ParamType.TYPE_BINARY_SINGLE)
                    .addParamAtPosition(4, clientModel.salt(), ParamType.TYPE_BINARY_SINGLE)
                    .isPrepared()
                    .update();
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error storing client information: " + e.getMessage());
            throw e;
        }
    }

}
