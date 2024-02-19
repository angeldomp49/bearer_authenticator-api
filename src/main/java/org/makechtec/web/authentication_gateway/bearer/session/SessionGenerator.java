package org.makechtec.web.authentication_gateway.bearer.session;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.postgres.PostgresEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.logging.Logger;

public class SessionGenerator {

    private static final Logger LOG = Logger.getLogger(SessionGenerator.class.getName());
    private final int sessionLifeTime;
    private final int sessionLifeUnits;
    private final ConnectionInformation connectionInformation;

    public SessionGenerator(int sessionLifeTime, int sessionLifeUnits, ConnectionInformation connectionInformation) {
        this.sessionLifeTime = sessionLifeTime;
        this.sessionLifeUnits = sessionLifeUnits;
        this.connectionInformation = connectionInformation;
    }


    public SessionInformation createForUser(String username) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        try {

            var userId =
                    new PostgresEngine<Long>(connectionInformation)
                            .queryString("""
                                    SELECT id FROM atepoztli__authentication_service__schema.users WHERE username = ?;
                                     """)
                            .isPrepared()
                            .addParamAtPosition(1, username, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getLong("id");
                            });

            var permissions = new ArrayList<String>();


            new PostgresEngine<Void>(connectionInformation)
                    .isPrepared()
                    .queryString("""
                            SELECT pinfo.*
                            FROM atepoztli__authentication_service__schema.users AS u
                            INNER JOIN atepoztli__authentication_service__schema.role_user AS r
                            ON r.user_id = u.id
                            INNER JOIN atepoztli__authentication_service__schema.permission_role AS p
                            ON p.role_id = r.role_id
                            INNER JOIN atepoztli__authentication_service__schema.permissions AS pinfo
                            ON p.permission_id = pinfo.id
                            WHERE u.id = ?;
                            """)
                    .addParamAtPosition(1, userId, ParamType.TYPE_LONG)
                    .run(resultSet -> {
                        while (resultSet.next()) {
                            permissions.add(resultSet.getString("name"));
                        }

                        return null;
                    });

            var expirationTime = Calendar.getInstance();
            expirationTime.add(sessionLifeUnits, sessionLifeTime);

            return new SessionInformation(
                    expirationTime,
                    false,
                    userId,
                    permissions
            );

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting permissions for user");
            throw e;
        }

    }

}
