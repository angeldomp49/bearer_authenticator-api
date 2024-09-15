package org.makechtec.web.authentication_gateway.app.lifecycle;

import org.makechtec.web.authentication_gateway.rate_limit.RateLimitTimeUnit;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.sql.SQLException;
import java.util.logging.Logger;

import static org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper.iocContainer;

@Component
public class ApplicationLifeCycleListener implements ApplicationListener<ApplicationReadyEvent> {

    private static final Logger LOG = Logger.getLogger(ApplicationLifeCycleListener.class.getName());

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {

        RateLimiter rateLimiter = (RateLimiter) iocContainer.getSingleton("rateLimiter");

        try {
            rateLimiter.registerNewRateLimit("login", 5, RateLimitTimeUnit.MINUTE, 15);
            rateLimiter.registerNewRateLimit("register", 5, RateLimitTimeUnit.MINUTE, 15);
            rateLimiter.registerNewRateLimit("csrf", 5, RateLimitTimeUnit.MINUTE, 15);
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Could not register rate-limiter: " + e.getMessage());
            throw new RuntimeException(e);
        }

    }


}
