package org.makechtec.web.authentication_gateway.ioc;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.web.authentication_gateway.app.properties.CrypographyInformation;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.sql.SQLException;
import java.util.Set;

@Component
public class IOCContainerBootstraper implements ApplicationListener<ApplicationStartedEvent> {

    public static EnvironmentContext globalContext;
    public static IOCContainer iocContainer;
    private final ConnectionPool connectionPool;

    public IOCContainerBootstraper(ConnectionPool connectionPool) {
        this.connectionPool = connectionPool;
    }

    @Override
    public void onApplicationEvent(ApplicationStartedEvent event) {

        try {
            connectionPool.boot();
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        globalContext = new EnvironmentContext();

        initializeContext(globalContext);

        iocContainer = new IOCContainer(globalContext);

        var beans = defineBeans();

        iocContainer.registerAll(beans);

        iocContainer.instanciateSingletons();
    }

    public Set<BeanInformation> defineBeans() {
        return BeansDefinition.beans();
    }

    private void initializeContext(EnvironmentContext context) {

        var globalDatabaseConnectionInformation = new ConnectionInformation(
                "",
                "",
                "",
                "",
                ""
        );

        var applicationSecretKey = "";

        var cryptographyConfiguration = new CrypographyInformation();
        cryptographyConfiguration.setSecretKey("");
        cryptographyConfiguration.setArgon2SettingsMemory(64000);
        cryptographyConfiguration.setArgon2SettingsIterations(8);
        cryptographyConfiguration.setArgon2SettingsParallelismFactor(8);

        context.setItem("globalDatabaseConnectionInformation", globalDatabaseConnectionInformation);
        context.setItem("applicationSecretKey", applicationSecretKey);
        context.setItem("cryptographyConfiguration", cryptographyConfiguration);

    }

}
