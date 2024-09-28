package org.makechtec.web.authentication_gateway.mock.ioc;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.web.authentication_gateway.plugins.bearer.CrypographyInformation;
import org.makechtec.web.authentication_gateway.core.spring_integration.http.admin.AdminController;
import org.makechtec.web.authentication_gateway.core.spring_integration.http.auth.AuthController;
import org.makechtec.web.authentication_gateway.core.spring_integration.http.csrf.CSRFController;
import org.makechtec.web.authentication_gateway.core.spring_integration.http.user.ExternalUserController;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.util.stream.Stream;

import static org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper.globalContext;
import static org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper.iocContainer;

@Component
public class IOCContainerBootstraperMock implements ApplicationListener<ApplicationStartedEvent> {

    private final ApplicationContext applicationContext;

    public IOCContainerBootstraperMock(ApplicationContext applicationContext) {
        this.applicationContext = applicationContext;
    }

    @Override
    public void onApplicationEvent(ApplicationStartedEvent event) {
        globalContext = new EnvironmentContext();

        initializeContext(globalContext);

        iocContainer = new IOCContainer(globalContext);


        iocContainer.registerAll(BeansDefinitionMock.beans());

        iocContainer.instanciateSingletons();

        injectManually();
    }

    private void initializeContext(EnvironmentContext context) {

        var globalDatabaseConnectionInformation = new ConnectionInformation(
                "",
                "",
                "",
                "",
                ""
        );

        var applicationSecretKey = "test";

        var cryptographyConfiguration = new CrypographyInformation();
        cryptographyConfiguration.setSecretKey("");
        cryptographyConfiguration.setArgon2SettingsMemory(64000);
        cryptographyConfiguration.setArgon2SettingsIterations(8);
        cryptographyConfiguration.setArgon2SettingsParallelismFactor(8);

        context.setItem("globalDatabaseConnectionInformation", globalDatabaseConnectionInformation);
        context.setItem("applicationSecretKey", applicationSecretKey);
        context.setItem("cryptographyConfiguration", cryptographyConfiguration);

    }

    private void injectManually() {

        Stream.of(
                applicationContext.getBean(AdminController.class),
                applicationContext.getBean(AuthController.class),
                applicationContext.getBean(CSRFController.class),
                applicationContext.getBean(ExternalUserController.class)
        ).forEach(ManuallyInjectable::inject);

    }

}
