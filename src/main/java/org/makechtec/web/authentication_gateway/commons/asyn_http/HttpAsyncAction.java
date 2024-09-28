package org.makechtec.web.authentication_gateway.commons.asyn_http;

import org.makechtec.software.ioc_container.env.EnvironmentContext;

public interface HttpAsyncAction {

    void perform(EnvironmentContext context);

    boolean hasSuccessfulFinished(EnvironmentContext context);

    FailedAsyncActionResponse createFailedResponse(EnvironmentContext context);

}
