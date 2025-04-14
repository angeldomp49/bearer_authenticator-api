package org.makechtec.web.authentication_gateway.resources.client.validation;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.resources.application.validation.ApplicationRateLimitValidator;
import org.makechtec.web.authentication_gateway.validation.rate_limit.RateLimit;
import org.makechtec.web.authentication_gateway.validation.rate_limit.RateLimitRegistry;

import java.sql.SQLException;
import java.util.logging.Logger;

public class ClientRateLimitValidator {

    private static final Logger LOG = Logger.getLogger(ApplicationRateLimitValidator.class.getName());
    private final ConnectionPool connectionPool;
    private final RateLimitRegistry registry;

    public ClientRateLimitValidator(ConnectionPool connectionPool, RateLimitRegistry registry) {
        this.connectionPool = connectionPool;
        this.registry = registry;
    }

    public boolean hasAttemptsThisClient(String applicationIP, String clientIP, String clientAgent, String rateLimitTitle) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {

            var totalOfAttemptsAvailable =
                    new WithPoolEngine<RateLimit>(connectionPool)
                            .isPrepared()
                            .queryString("""
                                    SELECT attempts, unit, time_quantity
                                    FROM atepoztli__authentication_service__schema.rate_limits
                                    WHERE title = ?;
                                    """)
                            .addParamAtPosition(1, rateLimitTitle, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return new RateLimit(
                                        resultSet.getInt("attempts"),
                                        resultSet.getString("unit"),
                                        resultSet.getInt("time_quantity")
                                );
                            });

            var beforeLimitFilter = registry.calculateFilterForTime(totalOfAttemptsAvailable);

            var queryWithTimeFilter = """
                    SELECT COUNT(*) AS result
                    FROM atepoztli__authentication_service__schema.client_attempts
                    WHERE application_ip = ?
                    AND client_ip = ?
                    AND client_agent = ?
                    AND created_at >= (NOW() - INTERVAL '${filter}');
                    """.replace("${filter}", beforeLimitFilter);

            var alreadyUsedAttempts =
                    new WithPoolEngine<Integer>(connectionPool)
                            .isPrepared()
                            .queryString(queryWithTimeFilter)
                            .addParamAtPosition(1, applicationIP, ParamType.TYPE_STRING)
                            .addParamAtPosition(2, clientIP, ParamType.TYPE_STRING)
                            .addParamAtPosition(3, clientAgent, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getInt("result");
                            });

            return registry.hasAvailableAttempts(alreadyUsedAttempts, totalOfAttemptsAvailable.attempts());

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting attempts for this client: " + e.getMessage());
            throw e;
        }
    }

    public void pushAttemptToThisClient(String applicationIP, String clientIP, String clientAgent) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {

            new WithPoolEngine<Void>(connectionPool)
                    .isPrepared()
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.client_attempts(application_ip, client_ip, client_agent, created_at)
                            VALUES(?,?, NOW());
                            """)
                    .addParamAtPosition(1, applicationIP, ParamType.TYPE_STRING)
                    .addParamAtPosition(2, clientIP, ParamType.TYPE_STRING)
                    .addParamAtPosition(3, clientAgent, ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem registering attempt in database: " + e.getMessage());
            throw e;
        }
    }

}
