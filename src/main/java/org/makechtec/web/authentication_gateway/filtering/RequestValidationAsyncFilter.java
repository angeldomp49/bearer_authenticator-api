package org.makechtec.web.authentication_gateway.filtering;

import org.makechtec.software.ioc_container.env.EnvironmentContext;

public interface RequestValidationAsyncFilter {

    boolean canPassRequest(EnvironmentContext context);

    ValidationFailedResponse createFailedResponse(EnvironmentContext context);

}
