package org.makechtec.web.authentication_gateway.core.bootstrap;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.web.authentication_gateway.core.spring_integration.AuthApiApplication;
import org.makechtec.web.authentication_gateway.core.beans.BeansDefinition;
import org.springframework.boot.SpringApplication;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class AuthenticationGatewayApplication {

    private final List<ApplicationPlugin> plugins = new ArrayList<>();
    private final Set<BeanInformation> beanDefinitions = new HashSet<>();
    private final EnvironmentContext globalState = new EnvironmentContext();
    private final IOCContainer container = new IOCContainer(globalState);

    public void boot(String[] args){
        registerPlugins();
        createGlobalVariables();
        onPreparedGlobalState();
        createBeans();
        onPreparedContainer();
        loadRestApplication(args);
        onLoadedRestApplication();
    }

    public void registerPlugins(){

    }

    public void createGlobalVariables(){
        var globalDatabaseConnectionInformation = new ConnectionInformation(
                "",
                "",
                "",
                "",
                ""
        );

        globalState.setItem("globalDatabaseConnectionInformation", globalDatabaseConnectionInformation);
    }

    public void onPreparedGlobalState(){
        plugins.forEach(plugin -> plugin.onPreparedGlobalState(globalState));
    }

    public void createBeans(){
        beanDefinitions.addAll(BeansDefinition.beans());
        beanDefinitions.addAll(
                plugins.stream()
                        .flatMap(plugin -> plugin.registerBeans(globalState).stream())
                        .collect(Collectors.toSet())
        );

        container.registerAll(beanDefinitions);

        container.instanciateSingletons();

    }

    public void onPreparedContainer(){

        var connectionPool = (ConnectionPool) container.getSingleton("globalSQLPoolConnection");

        try {
            connectionPool.boot();
        } catch (SQLException | IllegalAccessException | InstantiationException | ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        plugins.forEach(plugin -> plugin.onPreparedContainer(globalState, container));

    }

    public void loadRestApplication(String[] args){

        SpringApplication.run(AuthApiApplication.class, args);
    }

    public void onLoadedRestApplication(){
        plugins.forEach(plugin -> plugin.onLoadedRestApplication(globalState, container));
    }

    public EnvironmentContext getGlobalState() {
        return globalState;
    }

    public IOCContainer getContainer() {
        return container;
    }
}
