package org.makechtec.web.authentication_gateway.mock.ioc;

import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.ioc_container.ioc.BeanInformation;
import org.makechtec.software.ioc_container.ioc.IOCContainer;
import org.makechtec.software.ioc_container.ioc.InstanceScope;
import org.makechtec.software.sql_support.connection_pool.ConnectionPool;
import org.makechtec.software.sql_support.connection_pool.PooledConnection;
import org.makechtec.web.authentication_gateway.app.properties.CrypographyInformation;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.bearer.JWTTokenHandler;
import org.makechtec.web.authentication_gateway.bearer.session.SessionGenerator;
import org.makechtec.web.authentication_gateway.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.bearer.user.UserAuthenticator;
import org.makechtec.web.authentication_gateway.configuration_load.JSONConfigurationLoader;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.ioc.ActionsDefinition;
import org.makechtec.web.authentication_gateway.ioc.FiltersDefinition;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimitTimeUnit;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.mockito.Mockito;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class BeansDefinitionMock {

    public static Set<BeanInformation> beans() {

        var beans = new HashSet<BeanInformation>();

        beans.addAll(FiltersDefinition.beans());
        beans.addAll(ActionsDefinition.beans());

        beans.add(new BeanInformation(
                "csrfTokenHandler",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    class MockCSRFTokenHandler extends CSRFTokenHandler {

                        public MockCSRFTokenHandler(ConnectionPool connectionPool) {
                            super(connectionPool);
                        }

                        @Override
                        public void registerCSRFToken(String userIP, String userAgent, long expirationDate, String token) {

                        }

                        @Override
                        public boolean isValidCSRFToken(String userIP, String userAgent, String token) {
                            return true;
                        }

                        @Override
                        public void deleteCSRFToken(String token) {

                        }
                    }

                    var mock = new MockCSRFTokenHandler(
                            null
                    );


                    return mock;
                }
        ));

        beans.add(new BeanInformation(
                "bearerAuthenticationFactory",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];
                    var container = (IOCContainer) args[1];

                    var mock = Mockito.mock(BearerAuthenticationFactory.class);

                    var userAuthenticatorMock = Mockito.mock(UserAuthenticator.class);

                    var sessionGeneratorMock = Mockito.mock(SessionGenerator.class);

                    try {

                        when(userAuthenticatorMock.areValidCredentials(anyString(), anyString()))
                                .thenReturn(true);


                    } catch (SQLException | IllegalAccessException | InstantiationException |
                             ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }

                    when(mock.userAuthenticator())
                            .thenReturn(userAuthenticatorMock);

                    when(mock.sessionGenerator())
                            .thenReturn(sessionGeneratorMock);

                    when(mock.jwtTokenHandler())
                            .thenReturn(Mockito.mock(JWTTokenHandler.class));

                    return mock;
                },
                Stream.of("signaturePrinter", "passwordHasher").collect(Collectors.toSet())
        ));

        beans.add(new BeanInformation(
                "rateLimiter",
                InstanceScope.SINGLETON,
                args -> {
                    var container = (IOCContainer) args[1];

                    class MockRateLimiter extends RateLimiter {


                        public MockRateLimiter(ConnectionPool connectionPool) {
                            super(connectionPool);
                        }

                        @Override
                        public void registerNewRateLimit(String a, int b, RateLimitTimeUnit c, int d) {

                        }

                        @Override
                        public boolean hasAttemptsThisUser(String a, String b, String d) {
                            return true;
                        }

                        @Override
                        public void pushAttemptToThisUser(String a, String b) {

                        }

                    }

                    var mock = new MockRateLimiter(
                            null
                    );

                    return mock;
                }
        ));

        beans.add(new BeanInformation(
                "clientValidator",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    var mock = Mockito.mock(ClientValidator.class);

                    return mock;

                }
        ));

        beans.add(new BeanInformation(
                "signaturePrinter",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    return new SignaturePrinter((String) context.getItem("applicationSecretKey"));
                }
        ));

        beans.add(new BeanInformation(
                "passwordHasher",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    return new PasswordHasher((CrypographyInformation) context.getItem("cryptographyConfiguration"));
                }
        ));

        beans.add(new BeanInformation(
                "csrfTokenGenerator",
                InstanceScope.SINGLETON,
                args -> {
                    var context = (EnvironmentContext) args[0];

                    return new CSRFTokenGenerator((String) context.getItem("applicationSecretKey"));
                }
        ));

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

        beans.add(new BeanInformation(
                "globalSQLPoolConnection",
                InstanceScope.SINGLETON,
                args -> {

                    var pool = new ConnectionPool(Runtime.getRuntime().availableProcessors(), () -> new PooledConnection() {

                        @Override
                        public boolean isUsable() {
                            return true;
                        }

                        @Override
                        public Connection nativeConnection() {
                            return Mockito.mock(Connection.class);
                        }

                        @Override
                        public void close() throws SQLException {
                        }
                    });

                    try {
                        pool.boot();
                    } catch (SQLException | IllegalAccessException | InstantiationException |
                             ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }

                    return pool;
                }
        ));

        return beans;
    }

}
