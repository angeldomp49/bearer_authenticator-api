package org.makechtec.web.authentication_gateway.app.lifecycle;

import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.components.random_string.RandomStringGenerator;
import org.makechtec.web.authentication_gateway.commons.components.rate_limit.RateLimit;
import org.makechtec.web.authentication_gateway.commons.components.rate_limit.RateLimitRegistry;
import org.makechtec.web.authentication_gateway.commons.components.rate_limit.RateLimitSchema;
import org.makechtec.web.authentication_gateway.commons.components.rate_limit.RateLimitTimeUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import java.sql.SQLException;
import java.util.logging.Logger;

@Component
public class ApplicationLifeCycleListener implements ApplicationListener<ApplicationReadyEvent> {

    private static final Logger LOG = Logger.getLogger(ApplicationLifeCycleListener.class.getName());
    private final RateLimitRegistry rateLimitRegistry;
    private final CacheSystemTable cacheSystemTable;
    private final RandomStringGenerator randomStringGenerator;

    @Autowired
    public ApplicationLifeCycleListener(RateLimitRegistry rateLimitRegistry, CacheSystemTable cacheSystemTable, RandomStringGenerator randomStringGenerator) {
        this.rateLimitRegistry = rateLimitRegistry;
        this.cacheSystemTable = cacheSystemTable;
        this.randomStringGenerator = randomStringGenerator;
    }

    @Override
    public void onApplicationEvent(@NonNull ApplicationReadyEvent event) {

        cacheSystemTable.putCallback("temporaryApplicationSecretKey", randomStringGenerator::generateTemporarySecretKey);

        try {
            this.rateLimitRegistry.registerNewRateLimit(new RateLimitSchema(
                    """
                            {
                                "fields":[]
                            }
                            """,
                    new RateLimit(
                            "login", 
                            5, 
                            RateLimitTimeUnit.MINUTE.getName(), 
                            15
                    )
            ));
            this.rateLimitRegistry.registerNewRateLimit(
                    new RateLimitSchema(
                            """
                                    {
                                        "fields":[]
                                    }
                                    """,
                            new RateLimit(
                                    "register", 
                                    5, 
                                    RateLimitTimeUnit.MINUTE.getName(), 
                                    15
                            )
                    )
            );
            this.rateLimitRegistry.registerNewRateLimit(
                    new RateLimitSchema(
                            """
                                    {
                                        "fields":[]
                                    }
                                    """,
                            new RateLimit(
                                    "csrf", 
                                    5, 
                                    RateLimitTimeUnit.MINUTE.getName(), 
                                    15
                            )
                    )
            );
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Could not register rate-limiter: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

}
