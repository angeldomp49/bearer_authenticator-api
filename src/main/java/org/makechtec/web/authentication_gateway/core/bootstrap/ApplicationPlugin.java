package org.makechtec.web.authentication_gateway.core.bootstrap;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;

import java.util.Set;

public interface ApplicationPlugin {

    void onPreparedGlobalState(EnvironmentContext globalState);

    Set<BeanInformation> registerBeans(EnvironmentContext globalState);

    void onPreparedContainer(EnvironmentContext globalState, IOCContainer container);

    void onLoadedRestApplication(EnvironmentContext globalState, IOCContainer container);

}
