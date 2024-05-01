package org.makechtec.web.authentication_gateway.api.user;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.postgres.PostgresEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class UserDBConnection {

    private static final Logger LOG = Logger.getLogger(UserDBConnection.class.getName());
    private final ConnectionInformation connectionInformation;

    public UserDBConnection(ConnectionInformation connectionInformation) {
        this.connectionInformation = connectionInformation;
    }

    public void store(StoredUserModel user) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            new PostgresEngine<Void>(connectionInformation)
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.users
                            (username, email, hashed_password)
                            VALUES(?,?,?)
                            """)
                    .addParamAtPosition(1, user.username(), ParamType.TYPE_STRING)
                    .addParamAtPosition(2, user.email(), ParamType.TYPE_STRING)
                    .addParamAtPosition(3, user.hashedPassword(), ParamType.TYPE_STRING)
                    .isPrepared()
                    .update();
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error storing user");
            throw e;
        }
    }

}
