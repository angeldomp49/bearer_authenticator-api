package org.makechtec.web.authentication_gateway.commons.components.session;

import org.bouncycastle.util.encoders.Hex;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.ArgonSettings;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.SaltGenerator;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.JWTTokenGenerator;
import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;
import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.software.json_tree.builders.ArrayStringLeafBuilder;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.ResourceSessionValidator;

import java.nio.ByteBuffer;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.Optional;
import java.util.logging.Logger;

public class CommonSessionValidator implements ResourceSessionValidator {
    
    private static final String DATABASE_NAME = "base_database";
    private static final String SCHEMA_NAME = "atepoztli__authentication_service__schema";
    private static final String SESSIONS_TABLE = "resource__sessions";
    private static final String SECRET_KEYS_TABLE = "resource__secret_keys";
    private static final String RESOURCES_TABLE = "resource__resources";
    private static final String PIVOT_RESOURCE_ROLE_TABLE = "resource__resource_role";
    private static final String PIVOT_ROLE_PERMISSION_TABLE = "resource__role_permission";
    private static final String PERMISSIONS_TABLE = "resource__permissions";

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

            var hashed = mergeHashedWithSalt(resourceModel);
            return resourceModel.filter(value -> passwordHasher.matches(secret, hashed))
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
                    .queryString(String.format("""
                            SELECT resource.id, resource.specific_attributes
                            FROM %s.%s.%s AS resource
                            WHERE resource.access_key = ?;
                            """, DATABASE_NAME, SCHEMA_NAME, RESOURCES_TABLE))
                    .addParamAtPosition(1, accessKey, ParamType.TYPE_STRING)
                    .run(resultSet -> {
                        resultSet.next();

                        return new Object[]{
                                resultSet.getLong("id"),
                                resultSet.getString("specific_attributes")
                        };
                    });

            new WithPoolEngine<Void>(connectionPool)
                    .isPrepared()
                    .queryString(String.format("""
                            SELECT permission.name, resource.id
                            FROM %s.%s.%s AS resource
                                     INNER JOIN %s.%s.%s AS role
                                                ON role.resource_resource_id = resource.id
                                     INNER JOIN %s.%s.%s AS role_permission
                                                ON role_permission.resource_role_id = role.resource_role_id
                                     INNER JOIN %s.%s.%s AS permission
                                                ON role_permission.resource_permission_id = permission.id
                            WHERE resource.access_key = ?;
                            """, 
                            DATABASE_NAME, SCHEMA_NAME, RESOURCES_TABLE, 
                            DATABASE_NAME, SCHEMA_NAME, PIVOT_RESOURCE_ROLE_TABLE, 
                            DATABASE_NAME, SCHEMA_NAME, PIVOT_ROLE_PERMISSION_TABLE,
                            DATABASE_NAME, SCHEMA_NAME, PERMISSIONS_TABLE
                    ))
                    .addParamAtPosition(1, accessKey, ParamType.TYPE_STRING)
                    .run(resultSet -> {
                        while (resultSet.next()) {
                            permissions.add(resultSet.getString("name"));
                        }

                        return null;
                    });

            var expirationTime = Calendar.getInstance();
            expirationTime.add(Calendar.DAY_OF_MONTH, SESSION_EXPIRATION_DAYS);
            
            var permissionsString = permissionsJson(permissions).getLeafValue();

            var sessionId = new WithPoolEngine<Long>(connectionPool)
                    .isPrepared()
                    .queryString(String.format("""
                            INSERT INTO %s.%s.%s(resource_id, expiration_date, is_closed, permissions)
                            VALUES(?,?,?,?::json);
                            """, DATABASE_NAME, SCHEMA_NAME, SESSIONS_TABLE))
                    .addParamAtPosition(1, resourceInfo[0], ParamType.TYPE_LONG)
                    .addParamAtPosition(2, expirationTime.getTimeInMillis(), ParamType.TYPE_LONG)
                    .addParamAtPosition(3, false, ParamType.TYPE_BOOLEAN)
                    .addParamAtPosition(4, permissionsString, ParamType.TYPE_STRING)
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
                        .queryString(String.format("""
                                SELECT id, kind, access_key, hashed_secret, salt, specific_attributes
                                FROM %s.%s.%s
                                WHERE kind = ?
                                AND access_key = ?
                                LIMIT 1;
                                """, DATABASE_NAME, SCHEMA_NAME, RESOURCES_TABLE))
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
                                            resultSet.getString("access_key"),
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
                            .queryString(String.format("""
                                    SELECT id, secret_key
                                    FROM %s.%s.%s
                                    WHERE resource_id = ?
                                    LIMIT 1;
                                    """, DATABASE_NAME, SCHEMA_NAME, SECRET_KEYS_TABLE))
                            .addParamAtPosition(1, resourceId, ParamType.TYPE_LONG)
                            .isPrepared()
                            .run(resultSet -> {
                                if (!resultSet.next()) {
                                    return Optional.empty();
                                }

                                return Optional.of(resultSet.getString("secret_key"));

                            });
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Error reading secret key");
            throw new ControllerValidationException(e.getMessage());
        }
    }

    private static byte[] mergeArrays(byte[] array1, byte[] array2) {
        ByteBuffer buffer = ByteBuffer.allocate(array1.length + array2.length);
        buffer.put(array1);
        buffer.put(array2);
        return buffer.array();
    }

    private static String mergeHashedWithSalt(Optional<ResourceModel> resourceModel) {
        return new String(
                Hex.encode(
                        mergeArrays(
                                resourceModel.get().hashedSecret(),
                                resourceModel.get().salt()
                        )
                )
        );
    }
    
    private static ObjectLeaf permissionsJson(List<String> permissions) {
        var permissionsArray = ArrayStringLeafBuilder.builder();
        permissions.forEach(permissionsArray::add);
        
        return ObjectLeafBuilder.builder()
                .put("permissions", permissionsArray.build())
                .build();
    }
    
}
