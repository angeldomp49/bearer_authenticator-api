package org.makechtec.web.authentication_gateway.ioc;

import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.http.commons.filters.*;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FiltersDefinition {

    public static Set<BeanInformation> beans() {
        var beans = new HashSet<BeanInformation>();

        beans.add(new BeanInformation(
                "userRateLimitFilter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new UserRateLimitAsyncFilter(
                            (RateLimiter) container.getSingleton("rateLimiter"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("rateLimiter", "commonResponseBuilder").collect(Collectors.toSet())
        ));

        beans.add(new BeanInformation(
                "userCredentialsFilter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new UserCredentialsAsyncFilter(
                            (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
        ));

        beans.add(new BeanInformation(
                "clientCredentialsFilter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new ClientCredentialsAsyncFilter(
                            (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
        ));

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
                "csrfTokenFilter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new CSRFTokenAsyncFilter(
                            (CSRFTokenHandler) container.getSingleton("csrfTokenHandler"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("csrfTokenHandler", "commonResponseBuilder").collect(Collectors.toSet())
        ));

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

        return beans;
    }

}
