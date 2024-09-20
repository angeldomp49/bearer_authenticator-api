package org.makechtec.web.authentication_gateway.ioc;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.postgres.PostgresPooledConnectionCreator;
import org.makechtec.web.authentication_gateway.app.properties.CrypographyInformation;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.configuration_load.JSONConfigurationLoader;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;

import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class HandlersDefinition {

    public static Set<BeanInformation> beans() {
        Set<BeanInformation> beans = new HashSet<>();

        beans.add(new BeanInformation(
                "csrfTokenHandler",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new CSRFTokenHandler(
                            (ConnectionPool) container.getSingleton("globalSQLPoolConnection")
                    );
                }
        ));

        beans.add(new BeanInformation(
                "bearerAuthenticationFactory",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];
                    var container = (IOCContainer) args[1];

                    return new BearerAuthenticationFactory(
                            (ConnectionPool) container.getSingleton("globalSQLPoolConnection"),
                            (SignaturePrinter) container.getSingleton("signaturePrinter"),
                            (PasswordHasher) container.getSingleton("passwordHasher")
                    );
                },
                Stream.of("signaturePrinter", "passwordHasher").collect(Collectors.toSet())
        ));

        beans.add(new BeanInformation(
                "rateLimiter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new RateLimiter(
                            (ConnectionPool) container.getSingleton("globalSQLPoolConnection")
                    );
                }
        ));

        beans.add(new BeanInformation(
                "clientValidator",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new ClientValidator(
                            (ConnectionPool) container.getSingleton("globalSQLPoolConnection")
                    );
                }
        ));

        beans.add(new BeanInformation(
                "signaturePrinter",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    return new SignaturePrinter((String) context.getItem("applicationSecretKey"));
                }
        ));

        beans.add(new BeanInformation(
                "csrfTokenGenerator",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    return new CSRFTokenGenerator((String) context.getItem("applicationSecretKey"));
                }
        ));

        beans.add(new BeanInformation(
                "passwordHasher",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    return new PasswordHasher((CrypographyInformation) context.getItem("cryptographyConfiguration"));
                }
        ));

        beans.add(new BeanInformation(
                "commonResponseBuilder",
                InstanceScope.SINGLETON,
                args -> new CommonResponseBuilder()
        ));

        beans.add(new BeanInformation(
                "jsonConfigurationLoader",
                InstanceScope.SINGLETON,
                args -> new JSONConfigurationLoader()
        ));

        beans.add(new BeanInformation(
                "globalSQLPoolConnection",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    var connectionInformation = (ConnectionInformation) context.getItem("globalDatabaseConnectionInformation");

                    var pool = new ConnectionPool(Runtime.getRuntime().availableProcessors(), new PostgresPooledConnectionCreator(connectionInformation));

                    try {
                        pool.boot();
                    } catch (SQLException | IllegalAccessException | InstantiationException |
                             ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }

                    return pool;
                }
        ));

        return beans;
    }
}
