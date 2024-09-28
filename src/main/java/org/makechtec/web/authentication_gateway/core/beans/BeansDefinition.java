package org.makechtec.web.authentication_gateway.core.beans;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.postgres.PostgresPooledConnectionCreator;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.core.configuration_load.JSONConfigurationLoader;

import java.util.HashSet;
import java.util.Set;

public class BeansDefinition {

    public static Set<BeanInformation> beans() {

        Set<BeanInformation> beans = new HashSet<>();

        beans.add(new BeanInformation(
                "commonResponseBuilder",
                InstanceScope.SINGLETON,
                args -> new CommonResponseBuilder()
        ));

        beans.add(new BeanInformation(
                "jsonConfigurationLoader",
                InstanceScope.SINGLETON,
                args -> new JSONConfigurationLoader()
        ));

        beans.add(
                new BeanInformation(
                        "globalSQLPoolConnection",
                        InstanceScope.SINGLETON,
                        args -> {

                            var context = (EnvironmentContext) args[0];
                            var connectionInformation = (ConnectionInformation) context.getItem("globalDatabaseConnectionInformation");


                            return new ConnectionPool(Runtime.getRuntime().availableProcessors(), new PostgresPooledConnectionCreator(connectionInformation));
                        }
                )
        );

        return beans;
    }

}
