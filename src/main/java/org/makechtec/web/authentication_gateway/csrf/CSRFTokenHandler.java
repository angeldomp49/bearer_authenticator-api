package org.makechtec.web.authentication_gateway.csrf;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.Calendar;
import java.util.logging.Logger;

public class CSRFTokenHandler {

    private static final Logger LOG = Logger.getLogger(CSRFTokenHandler.class.getName());
    private final ConnectionPool connectionPool;

    public CSRFTokenHandler(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }


    public void registerCSRFToken(String userIP, String userAgent, long expirationDate, String token) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {


        try {

            new WithPoolEngine<Void>(connectionPool)
                    .isPrepared()
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.csrf_tokens(user_ip, user_agent, expiration_date, token)
                            VALUES(?,?,?,?,?);
                            """)
                    .addParamAtPosition(1, userIP, ParamType.TYPE_STRING)
                    .addParamAtPosition(2, userAgent, ParamType.TYPE_STRING)
                    .addParamAtPosition(4, expirationDate, ParamType.TYPE_LONG)
                    .addParamAtPosition(5, token, ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem registering csrf token in database");
            throw e;
        }

    }

    public boolean isValidCSRFToken(String userIP, String userAgent, String token) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        try {
            return
                    new WithPoolEngine<Boolean>(connectionPool)
                            .isPrepared()
                            .queryString("""
                                    SELECT COUNT(*) AS result
                                    FROM atepoztli__authentication_service__schema.csrf_tokens
                                    WHERE user_ip = ?
                                    AND user_agent = ?
                                    AND token = ?
                                    AND expiration_date > ?;
                                    """)
                            .addParamAtPosition(1, userIP, ParamType.TYPE_STRING)
                            .addParamAtPosition(2, userAgent, ParamType.TYPE_STRING)
                            .addParamAtPosition(4, token, ParamType.TYPE_STRING)
                            .addParamAtPosition(5, Calendar.getInstance().getTimeInMillis(), ParamType.TYPE_LONG)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getInt("result") > 0;
                            });

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting csrf token information from database: " + e.getMessage());
            throw e;
        }

    }

    public void deleteCSRFToken(String token) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            new WithPoolEngine<Void>(connectionPool)
                    .isPrepared()
                    .queryString("""
                            DELETE FROM atepoztli__authentication_service__schema.csrf_tokens
                            WHERE token = ?;
                            """)
                    .addParamAtPosition(1, token, ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem deleting csrf token in database");
            throw e;
        }
    }

}
