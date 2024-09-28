package org.makechtec.web.authentication_gateway.plugins.admin;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.web.authentication_gateway.core.bootstrap.ApplicationPlugin;

import java.util.Set;

public class AdminRestForUIPlugin implements ApplicationPlugin {
    @Override
    public void onPreparedGlobalState(EnvironmentContext globalState) {

    }

    @Override
    public Set<BeanInformation> registerBeans(EnvironmentContext globalState) {
        return Set.of();
    }

    @Override
    public void onPreparedContainer(EnvironmentContext globalState, IOCContainer container) {

    }

    @Override
    public void onLoadedRestApplication(EnvironmentContext globalState, IOCContainer container) {

    }
}
