package org.makechtec.web.authentication_gateway.app.lifecycle;

import org.makechtec.web.authentication_gateway.validation.rate_limit.RateLimitRegistry;
import org.makechtec.web.authentication_gateway.validation.rate_limit.RateLimitTimeUnit;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.sql.SQLException;
import java.util.logging.Logger;

@Component
public class ApplicationLifeCycleListener implements ApplicationListener<ApplicationReadyEvent> {

    private static final Logger LOG = Logger.getLogger(ApplicationLifeCycleListener.class.getName());
    private final RateLimitRegistry rateLimitRegistry;

    public ApplicationLifeCycleListener(RateLimitRegistry rateLimitRegistry) {
        this.rateLimitRegistry = rateLimitRegistry;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        try {
            this.rateLimitRegistry.registerNewRateLimit("login", 5, RateLimitTimeUnit.MINUTE, 15);
            this.rateLimitRegistry.registerNewRateLimit("register", 5, RateLimitTimeUnit.MINUTE, 15);
            this.rateLimitRegistry.registerNewRateLimit("csrf", 5, RateLimitTimeUnit.MINUTE, 15);
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Could not register rate-limiter: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

}
