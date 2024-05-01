package org.makechtec.web.authentication_gateway.csrf;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.postgres.PostgresEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.password.SaltGenerator;

import java.sql.SQLException;
import java.util.logging.Logger;

public class CSRFTokenHandler {

    private static final Logger LOG = Logger.getLogger(CSRFTokenHandler.class.getName());
    private final ConnectionInformation connectionInformation;
    private final CSRFTokenGenerator tokenGenerator;

    public CSRFTokenHandler(ConnectionInformation connectionInformation, CSRFTokenGenerator tokenGenerator) {
        this.connectionInformation = connectionInformation;
        this.tokenGenerator = tokenGenerator;
    }


    public String registerCSRFToken(String userIP, String userAgent, String clientIP, long expirationDate) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        var token = this.tokenGenerator.generateCSRFToken();

        try {

            new PostgresEngine<Void>(connectionInformation)
                    .isPrepared()
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.csrf_tokens(end_user_ip, user_agent, client_ip, expiration_date, token)
                            VALUES(?,?,?,?,?);
                            """)
                    .addParamAtPosition(1, userIP, ParamType.TYPE_STRING)
                    .addParamAtPosition(2, userAgent, ParamType.TYPE_STRING)
                    .addParamAtPosition(3, clientIP, ParamType.TYPE_STRING)
                    .addParamAtPosition(4, expirationDate, ParamType.TYPE_STRING)
                    .addParamAtPosition(5, token, ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem registering csrf token in database");
            throw e;
        }

        return token;
    }

    public String registerCSRFToken(String userIP, String userAgent, String clientIP, long expirationDate, long userId) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        var token = this.tokenGenerator.generateCSRFToken();

        try {

            new PostgresEngine<Void>(connectionInformation)
                    .isPrepared()
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.csrf_tokens(end_user_ip, user_agent, client_ip, expiration_date, user_id, token)
                            VALUES(?,?,?,?,?,?);
                            """)
                    .addParamAtPosition(1, userIP, ParamType.TYPE_STRING)
                    .addParamAtPosition(2, userAgent, ParamType.TYPE_STRING)
                    .addParamAtPosition(3, clientIP, ParamType.TYPE_STRING)
                    .addParamAtPosition(4, expirationDate, ParamType.TYPE_STRING)
                    .addParamAtPosition(5, userId, ParamType.TYPE_LONG)
                    .addParamAtPosition(6, token, ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem registering csrf token in database");
            throw e;
        }

        return token;
    }

    public boolean isValidCSRFToken(String userIP, String userAgent, String clientIP, String token) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {

        try {
            return
                new PostgresEngine<Boolean>(connectionInformation)
                        .isPrepared()
                        .queryString("""
                                SELECT COUNT(*) AS result
                                FROM atepoztli__authentication_service__schema.csrf_tokens
                                WHERE end_user_ip = ? AND user_agent = ? AND client_ip = ? AND token = ? AND expiration_date > NOW();
                                """)
                        .addParamAtPosition(1, userIP, ParamType.TYPE_STRING)
                        .addParamAtPosition(2, userAgent, ParamType.TYPE_STRING)
                        .addParamAtPosition(3, clientIP, ParamType.TYPE_STRING)
                        .addParamAtPosition(4, token, ParamType.TYPE_STRING)
                        .run(resultSet -> {
                            resultSet.next();

                            return resultSet.getInt("result") > 0;
                        });

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting csrf token information from database");
            throw e;
        }

    }

    public void deleteCSRFToken(String token) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            new PostgresEngine<Void>(connectionInformation)
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
