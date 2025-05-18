package org.makechtec.web.authentication_gateway.commons.components.rate_limit;

import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;

import java.sql.SQLException;
import java.util.logging.Logger;

public class RateLimitRegistry {

    private static final String SCHEMA = "atepoztli__authentication_service__schema";
    private static final String RATE_LIMITS_TABLE = "rate_limit__rate_limits";

    private static final Logger LOG = Logger.getLogger(RateLimitRegistry.class.getName());
    private final ConnectionPool connectionPool;

    public RateLimitRegistry(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    public void registerNewRateLimit(RateLimitSchema rateLimitSchema) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {

            new WithPoolEngine<Void>(connectionPool)
                    .isPrepared()
                    .queryString(String.format("""
                            INSERT INTO %s.%s(title, attempts, unit, time_quantity, schema)
                            VALUES(?,?,?,?,?::json)
                                ON CONFLICT (title) DO NOTHING;
                            """, SCHEMA, RATE_LIMITS_TABLE))
                    .addParamAtPosition(1, rateLimitSchema.rateLimit().title(), ParamType.TYPE_STRING)
                    .addParamAtPosition(2, rateLimitSchema.rateLimit().attempts(), ParamType.TYPE_INTEGER)
                    .addParamAtPosition(3, rateLimitSchema.rateLimit().unit(), ParamType.TYPE_STRING)
                    .addParamAtPosition(4, rateLimitSchema.rateLimit().timeQuantity(), ParamType.TYPE_INTEGER)
                    .addParamAtPosition(5, rateLimitSchema.schema(), ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem registering rate limit record in database for title: " + rateLimitSchema.rateLimit().title());
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
