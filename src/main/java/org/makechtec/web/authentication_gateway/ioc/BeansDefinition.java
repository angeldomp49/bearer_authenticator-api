package org.makechtec.web.authentication_gateway.ioc;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.web.authentication_gateway.app.properties.CrypographyInformation;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.configuration_load.JSONConfigurationLoader;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.http.commons.actions.DeleteCSRFTokenAction;
import org.makechtec.web.authentication_gateway.http.commons.actions.GenerateJWTTokenAction;
import org.makechtec.web.authentication_gateway.http.commons.actions.PushUserAttemptAction;
import org.makechtec.web.authentication_gateway.http.commons.filters.ClientAddressAsyncFilter;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class BeansDefinition {

    public static Set<BeanInformation> beans() {
        var beans = new HashSet<BeanInformation>();

        beans.add(new BeanInformation(
                "clientAddressFilter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new ClientAddressAsyncFilter(
                            (ClientValidator) container.getSingleton("clientValidator"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("clientValidator", "commonResponseBuilder").collect(Collectors.toSet())
        ));

        beans.add(new BeanInformation(
                "generateJWTTokenAction",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new GenerateJWTTokenAction(
                            (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
        ));

        beans.add(new BeanInformation(
                "deleteCSRFTokenAction",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new DeleteCSRFTokenAction(
                            (CSRFTokenHandler) container.getSingleton("csrfTokenHandler"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("csrfTokenHandler", "commonResponseBuilder").collect(Collectors.toSet())
        ));

        beans.add(new BeanInformation(
                "pushAttemptAction",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new PushUserAttemptAction(
                            (RateLimiter) container.getSingleton("rateLimiter"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("rateLimiter", "commonResponseBuilder").collect(Collectors.toSet())
        ));


        beans.add(new BeanInformation(
                "csrfTokenHandler",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    return new CSRFTokenHandler((ConnectionInformation) context.getItem("globalDatabaseConnectionInformation"));
                }
        ));

        beans.add(new BeanInformation(
                "bearerAuthenticationFactory",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];
                    var container = (IOCContainer) args[1];

                    return new BearerAuthenticationFactory(
                            (ConnectionInformation) context.getItem("globalDatabaseConnectionInformation"),
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
                    var context = (EnvironmentContext) args[0];

                    return new RateLimiter((ConnectionInformation) context.getItem("globalDatabaseConnectionInformation"));
                }
        ));

        beans.add(new BeanInformation(
                "clientValidator",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    return new ClientValidator((ConnectionInformation) context.getItem("globalDatabaseConnectionInformation"));
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

        return beans;
    }

}
