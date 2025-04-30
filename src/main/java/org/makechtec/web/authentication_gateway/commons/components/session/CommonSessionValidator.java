package org.makechtec.web.authentication_gateway.commons.components.session;

import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;
import org.makechtec.software.json_tree.builders.ArrayStringLeafBuilder;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ResourceSessionValidator;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Optional;
import java.util.logging.Logger;

public class CommonSessionValidator implements ResourceSessionValidator {

    private static final int SESSION_EXPIRATION_DAYS = 30;
    private static final Logger LOG = Logger.getLogger(CommonSessionValidator.class.getName());
    private final ConnectionPool connectionPool;
    private final PasswordHasherNative passwordHasher;
    private final JWTTokenGenerator tokenGenerator;

    public CommonSessionValidator(ConnectionPool connectionPool, PasswordHasherNative passwordHasher, JWTTokenGenerator tokenGenerator) {
        this.connectionPool = connectionPool;
        this.passwordHasher = passwordHasher;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public boolean areValidCredentials(String accessKey, String secret, String resourceKind) throws ControllerValidationException {
        try {
            var resourceModel = find(accessKey, resourceKind);

            return resourceModel.filter(value -> passwordHasher.matches(secret, new String(value.hashedSecret())))
                    .isPresent();
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error reading user for username");
            throw new ControllerValidationException(e.getMessage());
        }
    }

    @Override
    public AuthenticatedResourceSession createSession(String accessKey) throws ControllerValidationException {
        try {

            var permissions = new ArrayList<String>();

            var resourceInfo = new WithPoolEngine<Object[]>(connectionPool)
                    .isPrepared()
                    .queryString("""
                            SELECT resource.id, resource.specific_attributes
                            FROM base_database.atepoztli__authentication_service__schema.resource__resources AS resource
                            WHERE resource.access_key = ?;
                            """)
                    .addParamAtPosition(1, accessKey, ParamType.TYPE_LONG)
                    .run(resultSet -> {
                        resultSet.next();

                        return new Object[]{
                                resultSet.getLong("resource.id"),
                                resultSet.getString("resource.specific_attributes")
                        };
                    });

            new WithPoolEngine<Void>(connectionPool)
                    .isPrepared()
                    .queryString("""
                            SELECT permission.name
                            FROM base_database.atepoztli__authentication_service__schema.resource__resources AS resource
                                     INNER JOIN atepoztli__authentication_service__schema.resource_resource_role AS role
                                                ON role.resource_resource_id = resource.id
                                     INNER JOIN atepoztli__authentication_service__schema.resource__role_permission AS role_permission
                                                ON role_permission.resource_role_id = role.resource_role_id
                                     INNER JOIN atepoztli__authentication_service__schema.resource__permissions AS permission
                                                ON role_permission.resource_permission_id = permission.id
                            WHERE resource.access_key = ?;
                            """)
                    .addParamAtPosition(1, accessKey, ParamType.TYPE_LONG)
                    .run(resultSet -> {
                        while (resultSet.next()) {
                            permissions.add(resultSet.getString("name"));
                        }

                        return null;
                    });

            var expirationTime = Calendar.getInstance();
            expirationTime.add(Calendar.DAY_OF_MONTH, SESSION_EXPIRATION_DAYS);

            var sessionId = new WithPoolEngine<Long>(connectionPool)
                    .isPrepared()
                    .queryString("""
                            INSERT INTO resource_sessions(resource_id, expiration_date, is_closed, permissions
                            VALUES(?,?,?,?);
                            """)
                    .addParamAtPosition(1, resourceInfo[0], ParamType.TYPE_LONG)
                    .addParamAtPosition(2, expirationTime.getTimeInMillis(), ParamType.TYPE_LONG)
                    .addParamAtPosition(3, 0, ParamType.TYPE_INTEGER)
                    .addParamAtPosition(4, permissions, ParamType.TYPE_STRING)
                    .updateWithGeneratedKey(resultSet -> {
                        resultSet.next();
                        return resultSet.getLong("id");
                    });

            var session = new SessionInformation(
                    expirationTime,
                    false,
                    (long) resourceInfo[0],
                    permissions
            );

            return new AuthenticatedResourceSession(
                    session,
                    sessionId,
                    (long) resourceInfo[0],
                    (String) resourceInfo[1]
            );


        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting permissions for user");
            throw new ControllerValidationException(e.getMessage());
        }
    }


    @Override
    public String createJWT(AuthenticatedResourceSession sessionInformation) throws ControllerValidationException {
        var secretHashKey = resourceSecretHashKey(sessionInformation.resourceId());

        if (secretHashKey.isEmpty()) {
            throw new ControllerValidationException("Personal secret hash key is empty");
        }

        var header = ObjectLeafBuilder.builder()
                .put("alg", "HMAC-SHA512")
                .put("typ", "JWT")
                .build();

        var permissionsSet = ArrayStringLeafBuilder.builder();

        sessionInformation.sessionInformation().permissions().forEach(permissionsSet::add);

        var payload = ObjectLeafBuilder.builder()
                .put("expiration", sessionInformation.sessionInformation().expirationDate().getTimeInMillis())
                .put("sessionId", sessionInformation.sessionId())
                .put("resourceId", sessionInformation.resourceId())
                .put("isSessionClosed", sessionInformation.sessionInformation().isClosed())
                .put("permissions", permissionsSet.build())
                .put("attributes", permissionsSet.build())
                .build();

        return tokenGenerator.generateJWT(secretHashKey.get(), header, payload);
    }

    @Override
    public boolean isValidJWTSignature(String token) throws ControllerValidationException {
        var id = tokenGenerator.getJWTPayload(token).getLong("resourceId");
        var personalSecretHashKey = resourceSecretHashKey(id);

        return personalSecretHashKey.filter(s -> tokenGenerator.isValidSignature(token, s))
                .isPresent();
    }

    private Optional<ResourceModel> find(String accessKey, String resourceKind) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        return
                new WithPoolEngine<Optional<ResourceModel>>(connectionPool)
                        .queryString("""
                                SELECT id, kind, access_key, hashed_secret, salt, specific_attributes
                                FROM atepoztli__authentication_service__schema.session__resources
                                WHERE kind = ?
                                AND access_key = ?
                                LIMIT 1;
                                """)
                        .addParamAtPosition(1, resourceKind, ParamType.TYPE_STRING)
                        .addParamAtPosition(2, accessKey, ParamType.TYPE_STRING)
                        .isPrepared()
                        .run(resultSet -> {
                            if (!resultSet.next()) {
                                return Optional.empty();
                            }

                            return Optional.of(
                                    new ResourceModel(
                                            resultSet.getLong("id"),
                                            resultSet.getString("kind"),
                                            resultSet.getString("accessKey"),
                                            resultSet.getBytes("hashed_secret"),
                                            resultSet.getBytes("salt"),
                                            resultSet.getString("specific_attributes")
                                    )
                            );

                        });
    }

    private Optional<String> resourceSecretHashKey(long resourceId) throws ControllerValidationException {
        try {
            return
                    new WithPoolEngine<Optional<String>>(connectionPool)
                            .queryString("""
                                    SELECT id, personal_secret_hash_key
                                    FROM atepoztli__authentication_service__schema.resource__secret_keys
                                    WHERE resource_id = ?
                                    LIMIT 1;
                                    """)
                            .addParamAtPosition(1, resourceId, ParamType.TYPE_LONG)
                            .isPrepared()
                            .run(resultSet -> {
                                if (!resultSet.next()) {
                                    return Optional.empty();
                                }

                                return Optional.of(resultSet.getString("personal_secret_hash_key"));

                            });
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error reading secret key");
            throw new ControllerValidationException(e.getMessage());
        }
    }
}
