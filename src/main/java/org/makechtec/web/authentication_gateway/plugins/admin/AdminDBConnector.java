package org.makechtec.web.authentication_gateway.plugins.admin;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.plugins.bearer.user.User;

import java.sql.SQLException;
import java.util.Optional;
import java.util.logging.Logger;

public class AdminDBConnector {

    private static final Logger LOG = Logger.getLogger(AdminDBConnector.class.getName());
    private final ConnectionPool connectionPool;

    public AdminDBConnector(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }


    public boolean areValidCredentials(String username, String password) {
        Optional<User> user;
        try {
            user = getUser(username);
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            return false;
        }

        return user.map(value -> value.hashedPassword().equals(password)).orElse(false);

    }

    public Optional<User> getUser(String username) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            return
                    new WithPoolEngine<Optional<User>>(connectionPool)
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
