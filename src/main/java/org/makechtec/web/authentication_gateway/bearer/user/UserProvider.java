package org.makechtec.web.authentication_gateway.bearer.user;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.postgres.PostgresEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.Optional;
import java.util.logging.Logger;

public class UserProvider {

    private static final Logger LOG = Logger.getLogger(UserProvider.class.getName());
    private final ConnectionInformation connectionInformation;

    public UserProvider(ConnectionInformation connectionInformation) {
        this.connectionInformation = connectionInformation;
    }

    Optional<User> byUsername(String username) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            return
                    new PostgresEngine<Optional<User>>(connectionInformation)
                            .queryString("""
                                    SELECT id, username, hashed_password
                                    FROM atepoztli__authentication_service__schema.users
                                    WHERE username = ?
                                    LIMIT 1;
                                    """)
                            .addParamAtPosition(1, username, ParamType.TYPE_STRING)
                            .isPrepared()
                            .run(resultSet -> {
                                if (!resultSet.next()) {
                                    return Optional.empty();
                                }

                                return Optional.of(new User(
                                        resultSet.getString("username"),
                                        resultSet.getString("hashed_password"),
                                        resultSet.getLong("id")
                                ));

                            });
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error reading user for username");
            throw e;
        }
    }

}
