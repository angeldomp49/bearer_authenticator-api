package org.makechtec.web.authentication_gateway.resources.application.api;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class ApplicationDBConnection {
    
    private static final String DATABASE_NAME = "base_database";
    private static final String SCHEMA_NAME = "atepoztli__authentication_service__schema";
    private static final String APPLICATIONS_TABLE_NAME = "resource__resources";

    private static final Logger LOG = Logger.getLogger(ApplicationDBConnection.class.getName());

    private final ConnectionPool connectionPool;

    public ApplicationDBConnection(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    public void store(ApplicationModel applicationModel) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            new WithPoolEngine<Void>(connectionPool)
                    .queryString(String.format("""
                            INSERT INTO %s.%s.%s
                            (kind, access_key, hashed_secret, salt)
                            VALUES(?,?,?,?)
                            """, DATABASE_NAME, SCHEMA_NAME, APPLICATIONS_TABLE_NAME))
                    .addParamAtPosition(1, "application", ParamType.TYPE_STRING)
                    .addParamAtPosition(2, applicationModel.accessKey(), ParamType.TYPE_STRING)
                    .addParamAtPosition(3, applicationModel.hashedSecret(), ParamType.TYPE_BINARY_STRING)
                    .addParamAtPosition(4, applicationModel.salt(), ParamType.TYPE_BINARY_STRING)
                    .isPrepared()
                    .update();
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error storing application information: " + e.getMessage());
            throw e;
        }
    }

}
