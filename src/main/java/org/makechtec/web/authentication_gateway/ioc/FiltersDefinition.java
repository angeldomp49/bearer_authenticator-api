package org.makechtec.web.authentication_gateway.ioc;

import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.http.commons.filters.client.*;
import org.makechtec.web.authentication_gateway.http.commons.filters.external_user.ExternalUserCSRFTokenAsyncFilter;
import org.makechtec.web.authentication_gateway.http.commons.filters.external_user.ExternalUserCredentialsAsyncFilter;
import org.makechtec.web.authentication_gateway.http.commons.filters.external_user.ExternalUserJWTTokenAsyncFilter;
import org.makechtec.web.authentication_gateway.http.commons.filters.external_user.ExternalUserRateLimitAsyncFilter;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class FiltersDefinition {

    public static Set<BeanInformation> beans() {
        return Stream.of(forClient(), forExternalUser()).flatMap(Collection::stream).collect(Collectors.toSet());
    }

    public static Set<BeanInformation> forClient(){
        var beans = new HashSet<BeanInformation>();

        beans.add(new BeanInformation(
                "clientCredentialsAsyncFilter",
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
        ));

        beans.add(new BeanInformation(
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
        ));

        beans.add(new BeanInformation(
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
        ));

        beans.add(new BeanInformation(
                "clientJWTTokenAsyncFilter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new ClientJWTTokenAsyncFilter(
                            (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
        ));

        return beans;
    }

    public static Set<BeanInformation> forExternalUser(){
        var beans = new HashSet<BeanInformation>();

        beans.add(new BeanInformation(
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
        ));

        beans.add(new BeanInformation(
                "externalUserCredentialsAsyncFilter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new ExternalUserCredentialsAsyncFilter(
                            (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
        ));

        beans.add(new BeanInformation(
                "externalUserJWTTokenAsyncFilter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    return new ExternalUserJWTTokenAsyncFilter(
                            (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                            (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                    );
                },
                Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
        ));

        return beans;
    }



}
