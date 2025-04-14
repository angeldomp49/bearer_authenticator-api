package org.makechtec.web.authentication_gateway.validation.rate_limit;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class RateLimitRegistry {

    private static final Logger LOG = Logger.getLogger(RateLimitRegistry.class.getName());
    private final ConnectionPool connectionPool;

    public RateLimitRegistry(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    public void registerNewRateLimit(String title, int attempts, RateLimitTimeUnit timeUnit, int timeQuantity) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {

            new WithPoolEngine<Void>(connectionPool)
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
            LOG.severe("There was a problem registering rate limit record in database for title: " + title);
            throw e;
        }
    }

    public String calculateFilterForTime(RateLimit rateLimit) {
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

    public boolean hasAvailableAttempts(int currentAttempts, int allowedAttempts) {
        return (currentAttempts + 1) < allowedAttempts;
    }


}
