package org.makechtec.web.authentication_gateway.rate_limit;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.postgres.PostgresEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class RateLimiter {

    private static final Logger LOG = Logger.getLogger(RateLimiter.class.getName());
    private final ConnectionInformation connectionInformation;

    public RateLimiter(ConnectionInformation connectionInformation) {
        this.connectionInformation = connectionInformation;
    }

    public void registerNewRateLimit(String title, int attempts, RateLimitTimeUnit timeUnit, int timeQuantity) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {

            new PostgresEngine<Void>(connectionInformation)
                    .isPrepared()
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.rate_limits(title, attempts, unit, time_quantity)
                            VALUES(?,?,?,?)
                            ON CONFLICT (title) DO NOTHING;
                            """)
                    .addParamAtPosition(1, title, ParamType.TYPE_STRING)
                    .addParamAtPosition(2, attempts, ParamType.TYPE_INTEGER)
                    .addParamAtPosition(3, timeUnit.getName(), ParamType.TYPE_STRING)
                    .addParamAtPosition(4, timeQuantity, ParamType.TYPE_INTEGER)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem registering rate limit record in database for title: "+title);
            throw e;
        }
    }

    public boolean hasAttemptsThisClient(String userIP, String userAgent, String clientIP, String rateLimitTitle) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {

            var totalOfAttemptsAvailable =
                    new PostgresEngine<RateLimit>(connectionInformation)
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

            var beforeLimitFilter = calculateFilterForTime(totalOfAttemptsAvailable);

            var queryWithTimeFilter = """
                    SELECT COUNT(*) AS result
                    FROM atepoztli__authentication_service__schema.client_attempts
                    WHERE user_ip = ?
                    AND user_agent = ?
                    AND client_ip = ?
                    AND created_at >= (NOW() - INTERVAL '${filter}');
                    """.replace("${filter}", beforeLimitFilter);

            var alreadyUsedAttempts =
                    new PostgresEngine<Integer>(connectionInformation)
                            .isPrepared()
                            .queryString(queryWithTimeFilter)
                            .addParamAtPosition(1, userIP, ParamType.TYPE_STRING)
                            .addParamAtPosition(2, userAgent, ParamType.TYPE_STRING)
                            .addParamAtPosition(3, clientIP, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getInt("result");
                            });

            return hasAvailableAttempts(alreadyUsedAttempts, totalOfAttemptsAvailable.attempts());

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting attempts for this client: "+e.getMessage());
            throw e;
        }
    }

    private String calculateFilterForTime(RateLimit rateLimit) {
        String beforeLimitFilter = "";
        switch (rateLimit.unit()) {
            case ("DAY") -> {
                if (rateLimit.timeQuantity() == 1) {
                    beforeLimitFilter = "1 day";
                } else {
                    beforeLimitFilter = rateLimit.timeQuantity() + " days";
                }
            }
            case ("HOUR") -> {
                if (rateLimit.timeQuantity() == 1) {
                    beforeLimitFilter = "1 hour";
                } else {
                    beforeLimitFilter = rateLimit.timeQuantity() + " hours";
                }
            }
            case ("MINUTE") -> {
                if (rateLimit.timeQuantity() == 1) {
                    beforeLimitFilter = "1 minute";
                } else {
                    beforeLimitFilter = rateLimit.timeQuantity() + " minutes";
                }
            }
            case ("SECOND") -> {
                if (rateLimit.timeQuantity() == 1) {
                    beforeLimitFilter = "1 second";
                } else {
                    beforeLimitFilter = rateLimit.timeQuantity() + " seconds";
                }
            }
        }

        return beforeLimitFilter;
    }

    private boolean hasAvailableAttempts(int currentAttempts, int allowedAttempts) {
        return (currentAttempts + 1) < allowedAttempts;
    }

    public void pushAttemptToThisClient(String userIP, String userAgent, String clientIP) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {

            new PostgresEngine<Void>(connectionInformation)
                    .isPrepared()
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.client_attempts(user_ip, user_agent, client_ip, created_at)
                            VALUES(?,?,?, NOW());
                            """)
                    .addParamAtPosition(1, userIP, ParamType.TYPE_STRING)
                    .addParamAtPosition(2, userAgent, ParamType.TYPE_STRING)
                    .addParamAtPosition(3, clientIP, ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem registering attempt in database: "+e.getMessage());
            throw e;
        }
    }
}
