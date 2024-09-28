package org.makechtec.web.authentication_gateway.plugins.bearer;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.web.authentication_gateway.core.bootstrap.ApplicationPlugin;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.plugins.bearer.filters.ClientCredentialsAsyncFilter;
import org.makechtec.web.authentication_gateway.plugins.bearer.filters.ClientJWTTokenAsyncFilter;
import org.makechtec.web.authentication_gateway.plugins.bearer.filters.ExternalUserCredentialsAsyncFilter;
import org.makechtec.web.authentication_gateway.plugins.bearer.filters.ExternalUserJWTTokenAsyncFilter;
import org.makechtec.web.authentication_gateway.plugins.bearer.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.plugins.bearer.token.SignaturePrinter;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class BearerAuthenticationPlugin implements ApplicationPlugin {
    @Override
    public void onPreparedGlobalState(EnvironmentContext globalState) {
        var cryptographyConfiguration = new CrypographyInformation();
        cryptographyConfiguration.setSecretKey("");
        cryptographyConfiguration.setArgon2SettingsMemory(64000);
        cryptographyConfiguration.setArgon2SettingsIterations(8);
        cryptographyConfiguration.setArgon2SettingsParallelismFactor(8);

        globalState.setItem("cryptographyConfiguration", cryptographyConfiguration);
    }

    @Override
    public Set<BeanInformation> registerBeans(EnvironmentContext globalState) {
        return Set.of(
                new BeanInformation(
                        "passwordHasher",
                        InstanceScope.SINGLETON,
                        args -> new PasswordHasher((CrypographyInformation) globalState.getItem("cryptographyConfiguration"))
                ),
                new BeanInformation(
                        "signaturePrinter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var crypographyInformation = (CrypographyInformation) globalState.getItem("cryptographyConfiguration");

                            return new SignaturePrinter(crypographyInformation.getSecretKey());
                        }
                ),
                new BeanInformation(
                        "bearerAuthenticationFactory",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new BearerAuthenticationFactory(
                                    (ConnectionPool) container.getSingleton("globalSQLPoolConnection"),
                                    (SignaturePrinter) container.getSingleton("signaturePrinter"),
                                    (PasswordHasher) container.getSingleton("passwordHasher")
                            );
                        },
                        Stream.of("signaturePrinter", "passwordHasher").collect(Collectors.toSet())
                ),
                new BeanInformation(
                        "clientCredentialsAsyncFilter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ClientCredentialsAsyncFilter(
                                    (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
                ),
                new BeanInformation(
                        "clientJWTTokenAsyncFilter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ClientJWTTokenAsyncFilter(
                                    (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
                ),
                new BeanInformation(
                        "externalUserCredentialsAsyncFilter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ExternalUserCredentialsAsyncFilter(
                                    (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
                ),
                new BeanInformation(
                        "externalUserJWTTokenAsyncFilter",
                        InstanceScope.SINGLETON,
                        args -> {
                            var container = (IOCContainer) args[1];

                            return new ExternalUserJWTTokenAsyncFilter(
                                    (BearerAuthenticationFactory) container.getSingleton("bearerAuthenticationFactory"),
                                    (CommonResponseBuilder) container.getSingleton("commonResponseBuilder")
                            );
                        },
                        Stream.of("bearerAuthenticationFactory", "commonResponseBuilder").collect(Collectors.toSet())
                )
        );
    }

    @Override
    public void onPreparedContainer(EnvironmentContext globalState, IOCContainer container) {

    }

    @Override
    public void onLoadedRestApplication(EnvironmentContext globalState, IOCContainer container) {

    }


}
