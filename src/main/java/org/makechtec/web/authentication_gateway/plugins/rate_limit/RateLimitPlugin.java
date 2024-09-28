package org.makechtec.web.authentication_gateway.plugins.rate_limit;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.core.bootstrap.ApplicationPlugin;
import org.makechtec.web.authentication_gateway.plugins.rate_limit.filters.ClientRateLimitAsyncFilter;
import org.makechtec.web.authentication_gateway.plugins.rate_limit.filters.ExternalUserRateLimitAsyncFilter;

import java.sql.SQLException;
import java.util.Set;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper.iocContainer;

public class RateLimitPlugin implements ApplicationPlugin {

    private static final Logger LOG = Logger.getLogger(RateLimitPlugin.class.getName());

    @Override
    public void onPreparedGlobalState(EnvironmentContext globalState) {

    }

    @Override
    public Set<BeanInformation> registerBeans(EnvironmentContext globalState) {
        return Set.of(
                new BeanInformation(
                        "rateLimiter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new RateLimiter(
                                    (ConnectionPool) container.getSingleton("globalSQLPoolConnection")
                            );
                        }
                ),
                new BeanInformation(
                        "clientRateLimitAsyncFilter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ClientRateLimitAsyncFilter(
                                    (RateLimiter) container.getSingleton("rateLimiter"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("rateLimiter", "commonResponseBuilder").collect(Collectors.toSet())
                ),
                new BeanInformation(
                        "externalUserRateLimitAsyncFilter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ExternalUserRateLimitAsyncFilter(
                                    (RateLimiter) container.getSingleton("rateLimiter"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("rateLimiter", "commonResponseBuilder").collect(Collectors.toSet())
                )
        );
    }

    @Override
    public void onPreparedContainer(EnvironmentContext globalState, IOCContainer container) {
        var rateLimiter = (RateLimiter) iocContainer.getSingleton("rateLimiter");

        try {
            rateLimiter.registerNewRateLimit("login", 5, RateLimitTimeUnit.MINUTE, 15);
            rateLimiter.registerNewRateLimit("register", 5, RateLimitTimeUnit.MINUTE, 15);
            rateLimiter.registerNewRateLimit("csrf", 5, RateLimitTimeUnit.MINUTE, 15);
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("Could not register rate-limiter: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    @Override
    public void onLoadedRestApplication(EnvironmentContext globalState, IOCContainer container) {

    }


}
