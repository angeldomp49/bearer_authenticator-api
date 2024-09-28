package org.makechtec.web.authentication_gateway.plugins.csrf;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.web.authentication_gateway.core.bootstrap.ApplicationPlugin;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.plugins.csrf.actions.GenerateCSRFTokenAction;
import org.makechtec.web.authentication_gateway.plugins.csrf.filters.ClientCSRFTokenAsyncFilter;
import org.makechtec.web.authentication_gateway.plugins.csrf.filters.ClientWhiteListAsyncFilter;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class CSRFPlugin implements ApplicationPlugin {
    @Override
    public void onPreparedGlobalState(EnvironmentContext globalState) {

    }

    @Override
    public Set<BeanInformation> registerBeans(EnvironmentContext globalState) {
        return Set.of(
                new BeanInformation(
                        "csrfTokenGenerator",
                        InstanceScope.SINGLETON,
                        args -> {
                            var context = (EnvironmentContext) args[0];

                            return new CSRFTokenGenerator((String) context.getItem("applicationSecretKey"));
                        }
                ),
                new BeanInformation(
                        "clientValidator",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ClientValidator(
                                    (ConnectionPool) container.getSingleton("globalSQLPoolConnection")
                            );
                        }
                ),
                new BeanInformation(
                        "csrfTokenHandler",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new CSRFTokenHandler(
                                    (ConnectionPool) container.getSingleton("globalSQLPoolConnection")
                            );
                        }
                ),
                new BeanInformation(
                        "clientCSRFTokenAsyncFilter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ClientCSRFTokenAsyncFilter(
                                    (CSRFTokenHandler) container.getSingleton("csrfTokenHandler"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("csrfTokenHandler", "commonResponseBuilder").collect(Collectors.toSet())
                ),
                new BeanInformation(
                        "clientWhiteListAsyncFilter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ClientWhiteListAsyncFilter(
                                    (ClientValidator) container.getSingleton("clientValidator"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("clientValidator", "commonResponseBuilder").collect(Collectors.toSet())
                ),
                new BeanInformation(
                        "generateCSRFTokenAction",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new GenerateCSRFTokenAction(
                                    (CSRFTokenGenerator) container.getSingleton("csrfTokenGenerator"),
                                    (CSRFTokenHandler) container.getSingleton("csrfTokenHandler"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("csrfTokenGenerator", "csrfTokenHandler", "commonResponseBuilder").collect(Collectors.toSet())
                )
        );
    }

    @Override
    public void onPreparedContainer(EnvironmentContext globalState, IOCContainer container) {

    }

    @Override
    public void onLoadedRestApplication(EnvironmentContext globalState, IOCContainer container) {

    }


}
