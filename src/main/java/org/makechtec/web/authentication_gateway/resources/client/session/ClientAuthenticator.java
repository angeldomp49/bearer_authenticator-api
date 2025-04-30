package org.makechtec.web.authentication_gateway.resources.client.session;

import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasher;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;
import org.makechtec.software.json_tree.builders.ArrayStringLeafBuilder;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Optional;
import java.util.logging.Logger;

public class ClientAuthenticator {

    private static final int SESSION_EXPIRATION_DAYS = 30;
    private static final Logger LOG = Logger.getLogger(ClientAuthenticator.class.getName());

    private final PasswordHasher passwordHasher;
    private final ConnectionPool connectionPool;
    private final JWTTokenGenerator jwtTokenGenerator;


    public ClientAuthenticator(PasswordHasher passwordHasher, ConnectionPool connectionPool, JWTTokenGenerator jwtTokenGenerator) {
        this.passwordHasher = passwordHasher;
        this.connectionPool = connectionPool;
        this.jwtTokenGenerator = jwtTokenGenerator;
    }

    public boolean isValidJWTSignature(String token) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        var id = jwtTokenGenerator.getJWTPayload(token).getLong("clientId");
        var personalSecretHashKey = personalSecretHashKey(id);

        return personalSecretHashKey.filter(s -> jwtTokenGenerator.isValidSignature(token, s))
                .isPresent();

    }

    public String createJWT(SessionInformation sessionInformation) throws SQLException, InstantiationException, IllegalAccessException, ClassNotFoundException {
        var personalSecretHashKey = personalSecretHashKey(sessionInformation.userId());

        if (personalSecretHashKey.isEmpty()) {
            throw new SQLException("Personal secret hash key is empty");
        }

        var header = ObjectLeafBuilder.builder()
                .put("alg", "HMAC-SHA512")
                .put("typ", "JWT")
                .build();

        var permissionsSet = ArrayStringLeafBuilder.builder();

        sessionInformation.permissions().forEach(permissionsSet::add);

        var payload = ObjectLeafBuilder.builder()
                .put("exp", sessionInformation.expirationDate().getTimeInMillis())
                .put("clientId", sessionInformation.userId())
                .put("isClosed", sessionInformation.isClosed())
                .put("permissions", permissionsSet.build())
                .build();

        return jwtTokenGenerator.generateJWT(personalSecretHashKey.get(), header, payload);
    }

    public boolean areValidCredentials(String username, String password) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        var application = byUsername(username);

        return application.filter(value -> passwordHasher.matches(password, new String(value.hashedPassword())))
                .isPresent();
    }

    public SessionInformation createSession(String username) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {

            var clientId =
                    new WithPoolEngine<Long>(connectionPool)
                            .queryString("""
                                    SELECT id FROM atepoztli__authentication_service__schema.clients WHERE access_key = ?;
                                    """)
                            .isPrepared()
                            .addParamAtPosition(1, username, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getLong("id");
                            });

            var permissions = new ArrayList<String>();


            new WithPoolEngine<Void>(connectionPool)
                    .isPrepared()
                    .queryString("""
                            SELECT pinfo.*
                            FROM atepoztli__authentication_service__schema.clients AS u
                            INNER JOIN atepoztli__authentication_service__schema.client_role_client AS r
                            ON r.user_id = u.id
                            INNER JOIN atepoztli__authentication_service__schema.client_permission_client_role AS p
                            ON p.role_id = r.role_id
                            INNER JOIN atepoztli__authentication_service__schema.client_permissions AS pinfo
                            ON p.permission_id = pinfo.id
                            WHERE u.id = ?;
                            """)
                    .addParamAtPosition(1, clientId, ParamType.TYPE_LONG)
                    .run(resultSet -> {
                        while (resultSet.next()) {
                            permissions.add(resultSet.getString("name"));
                        }

                        return null;
                    });

            var expirationTime = Calendar.getInstance();
            expirationTime.add(Calendar.DAY_OF_MONTH, SESSION_EXPIRATION_DAYS);

            return new SessionInformation(
                    expirationTime,
                    false,
                    clientId,
                    permissions
            );

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting permissions for user");
            throw e;
        }
    }

    private Optional<ClientAuthenticationModel> byUsername(String username) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            return
                    new WithPoolEngine<Optional<ClientAuthenticationModel>>(connectionPool)
                            .queryString("""
                                    SELECT id, username, hashed_password
                                    FROM atepoztli__authentication_service__schema.clients
                                    WHERE username = ?
                                    LIMIT 1;
                                    """)
                            .addParamAtPosition(1, username, ParamType.TYPE_STRING)
                            .isPrepared()
                            .run(resultSet -> {
                                if (!resultSet.next()) {
                                    return Optional.empty();
                                }

                                return Optional.of(new ClientAuthenticationModel(
                                        resultSet.getLong("id"),
                                        resultSet.getString("username"),
                                        resultSet.getBytes("password"),
                                        resultSet.getBytes("salt")
                                ));

                            });
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error reading user for username");
            throw e;
        }
    }


    private Optional<String> personalSecretHashKey(long clientId) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            return
                    new WithPoolEngine<Optional<String>>(connectionPool)
                            .queryString("""
                                    SELECT id, personal_secret_hash_key
                                    FROM atepoztli__authentication_service__schema.client_personal_secret_hash_keys
                                    WHERE client_id = ?
                                    LIMIT 1;
                                    """)
                            .addParamAtPosition(1, clientId, ParamType.TYPE_LONG)
                            .isPrepared()
                            .run(resultSet -> {
                                if (!resultSet.next()) {
                                    return Optional.empty();
                                }

                                return Optional.of(resultSet.getString("personal_secret_hash_key"));

                            });
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error reading user for username");
            throw e;
        }
    }


}
