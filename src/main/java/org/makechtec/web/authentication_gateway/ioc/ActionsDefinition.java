package org.makechtec.web.authentication_gateway.ioc;

import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.http.commons.actions.DeleteCSRFTokenAction;
import org.makechtec.web.authentication_gateway.http.commons.actions.GenerateCSRFTokenAction;
import org.makechtec.web.authentication_gateway.http.commons.actions.GenerateJWTTokenAction;
import org.makechtec.web.authentication_gateway.http.commons.actions.PushUserAttemptAction;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ActionsDefinition {

    public static Set<BeanInformation> beans() {
        var beans = new HashSet<BeanInformation>();

        beans.add(new BeanInformation(
                "pushUserAttemptAction",
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

        return beans;
    }

}
