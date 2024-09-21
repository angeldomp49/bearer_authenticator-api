package org.makechtec.web.authentication_gateway.ioc.definitions;

import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.http.commons.actions.GenerateCSRFTokenAction;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ActionsDefinition {

    public static Set<BeanInformation> beans() {
        var beans = new HashSet<BeanInformation>();


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


        return beans;
    }

}
