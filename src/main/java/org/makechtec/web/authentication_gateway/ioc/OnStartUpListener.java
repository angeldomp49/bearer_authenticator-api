package org.makechtec.web.authentication_gateway.ioc;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

@Component
public class OnStartUpListener implements ApplicationListener<ApplicationReadyEvent> {

    public static EnvironmentContext globalContext;
    public static IOCContainer iocContainer;

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event){
        globalContext = new EnvironmentContext();

        iocContainer = new IOCContainer(globalContext);

        iocContainer.registerAll(BeansDefinition.beans());

        iocContainer.instanciateSingletons();
    }

}
