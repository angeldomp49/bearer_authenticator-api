package org.makechtec.web.authentication_gateway.http.commons.filters;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationAsyncFilter;
import org.makechtec.web.authentication_gateway.filtering.ValidationFailedResponse;

public class ClientCredentialsAsyncFilter implements RequestValidationAsyncFilter {



    @Override
    public boolean canPassRequest(EnvironmentContext context) {
        return false;
    }

    @Override
    public ValidationFailedResponse createFailedResponse(EnvironmentContext context) {
        return null;
    }


}
