package org.makechtec.web.authentication_gateway.commons.components.rate_limit;

import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.WithPoolEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidationException;
import org.makechtec.web.authentication_gateway.commons.http.validators.RateLimitValidator;

import java.sql.SQLException;
import java.util.Map;
import java.util.logging.Logger;

public class CommonRateLimitValidator implements RateLimitValidator {
    
    private static final String SCHEMA = "atepoztli__authentication_service__schema";
    private static final String CLIENT_ATTEMPTS_TABLE = "rate_limit__client_attempts";
    private static final String RATE_LIMITS_TABLE = "rate_limit__rate_limits";

    private static final Logger LOG = Logger.getLogger(CommonRateLimitValidator.class.getName());
    private final ConnectionPool connectionPool;
    private final RateLimitRegistry registry;

    public CommonRateLimitValidator(ConnectionPool connectionPool, RateLimitRegistry registry) {
        this.connectionPool = connectionPool;
        this.registry = registry;
    }

    @Override
    public boolean hasAttemptsAvailable(Map<String, String> filters, String rateLimitDefinitionName) throws ControllerValidationException {

        try {

            var filtersJson = fromMap(filters);


            var totalOfAttemptsAvailable = getTotalOfAttemptsAvailable(rateLimitDefinitionName);

            var beforeLimitFilter = registry.calculateFilterForTime(totalOfAttemptsAvailable.rateLimit());


            var queryWithTimeFilter = String.format("""
                    SELECT COUNT(*) AS result
                    FROM %s.%s
                    where title = ?
                    AND %s.rate_limit__compare_schema(?::json, ?::json)
                    AND created_at >= (NOW() - INTERVAL '%s');
                    """, SCHEMA, CLIENT_ATTEMPTS_TABLE, SCHEMA, beforeLimitFilter
            );

            var alreadyUsedAttempts =
                    new WithPoolEngine<Integer>(connectionPool)
                            .isPrepared()
                            .queryString(queryWithTimeFilter)
                            .addParamAtPosition(1, rateLimitDefinitionName, ParamType.TYPE_STRING)
                            .addParamAtPosition(2, totalOfAttemptsAvailable.schema(), ParamType.TYPE_STRING)
                            .addParamAtPosition(3, filtersJson.getLeafValue(), ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getInt("result");
                            });

            return registry.hasAvailableAttempts(alreadyUsedAttempts, totalOfAttemptsAvailable.rateLimit().attempts());

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting attempts for this client: " + e.getMessage());
            throw new ControllerValidationException(e.getMessage());
        }
    }

    private RateLimitSchema getTotalOfAttemptsAvailable(String rateLimitDefinitionName) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        return new WithPoolEngine<RateLimitSchema>(connectionPool)
                .isPrepared()
                .queryString(String.format("""
                        SELECT title, attempts, unit, time_quantity, schema
                        FROM %s.%s
                        WHERE title = ?;
                        """,SCHEMA, RATE_LIMITS_TABLE))
                .addParamAtPosition(1, rateLimitDefinitionName, ParamType.TYPE_STRING)
                .run(resultSet -> {
                    resultSet.next();

                    return new RateLimitSchema(
                            resultSet.getString("schema"),
                            new RateLimit(
                                    resultSet.getString("title"),
                                    resultSet.getInt("attempts"),
                                    resultSet.getString("unit"),
                                    resultSet.getInt("time_quantity")
                            )
                    );
                });
    }

    @Override
    public void sumOneAttempt(Map<String, String> filters, String rateLimitDefinitionName) throws ControllerValidationException {
        try {

            var filtersJson = fromMap(filters);

            new WithPoolEngine<Void>(connectionPool)
                    .isPrepared()
                    .queryString(String.format("""
                            INSERT INTO %s.%s(title, obj)
                            VALUES(?,?::json);
                            """, SCHEMA, CLIENT_ATTEMPTS_TABLE))
                    .addParamAtPosition(1, rateLimitDefinitionName, ParamType.TYPE_STRING)
                    .addParamAtPosition(2, filtersJson.getLeafValue(), ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem registering attempt in database: " + e.getMessage());
            throw new ControllerValidationException(e.getMessage());
        }
    }

    private ObjectLeaf fromMap(Map<String, String> filters) {
        var filtersJson = ObjectLeafBuilder.builder();

        filters.forEach(filtersJson::put);

        return filtersJson.build();
    }

}
