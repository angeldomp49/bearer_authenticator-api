package org.makechtec.web.authentication_gateway.core.spring_integration.configuration;

import org.makechtec.web.authentication_gateway.commons.asyn_http.HttpAsyncActionConfigurer;
import org.makechtec.web.authentication_gateway.commons.filtering.RequestValidationFilterConfigurer;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.core.spring_integration.AuthApiApplication;
import org.makechtec.web.authentication_gateway.core.spring_integration.http.admin.AdminController;
import org.makechtec.web.authentication_gateway.core.spring_integration.http.auth.AuthController;
import org.makechtec.web.authentication_gateway.core.spring_integration.http.csrf.CSRFController;
import org.makechtec.web.authentication_gateway.core.spring_integration.http.user.ExternalUserController;
import org.makechtec.web.authentication_gateway.plugins.bearer.BearerAuthenticationFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SpringControllerConfiguration {

    @Bean
    public AdminController adminController() {

        return new AdminController(
                (RequestValidationFilterConfigurer) AuthApiApplication.application.getContainer().getSingleton("requestValidationFilterConfigurer"),
                (HttpAsyncActionConfigurer) AuthApiApplication.application.getContainer().getSingleton("httpAsyncActionConfigurer"),
                (CommonResponseBuilder) AuthApiApplication.application.getContainer().getSingleton("commonResponseBuilder")
        );

    }

    @Bean
    public AuthController authController() {

        return new AuthController(
                (BearerAuthenticationFactory) AuthApiApplication.application.getContainer().getSingleton("bearerAuthenticationFactory"),
                (CommonResponseBuilder) AuthApiApplication.application.getContainer().getSingleton("commonResponseBuilder"),
                (RequestValidationFilterConfigurer) AuthApiApplication.application.getContainer().getSingleton("requestValidationFilterConfigurer"),
                (HttpAsyncActionConfigurer) AuthApiApplication.application.getContainer().getSingleton("httpAsyncActionConfigurer")
        );

    }

    @Bean
    public CSRFController csrfController() {

        return new CSRFController(
                (RequestValidationFilterConfigurer) AuthApiApplication.application.getContainer().getSingleton("requestValidationFilterConfigurer"),
                (HttpAsyncActionConfigurer) AuthApiApplication.application.getContainer().getSingleton("httpAsyncActionConfigurer"),
                (CommonResponseBuilder) AuthApiApplication.application.getContainer().getSingleton("commonResponseBuilder")
        );

    }

    @Bean
    public ExternalUserController externalUserController() {

        return new ExternalUserController(
                (CommonResponseBuilder) AuthApiApplication.application.getContainer().getSingleton("commonResponseBuilder"),
                (RequestValidationFilterConfigurer) AuthApiApplication.application.getContainer().getSingleton("requestValidationFilterConfigurer"),
                (HttpAsyncActionConfigurer) AuthApiApplication.application.getContainer().getSingleton("httpAsyncActionConfigurer")
        );

    }

}
