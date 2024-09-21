package org.makechtec.web.authentication_gateway.http.user;

import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.api.user.UserDBConnection;
import org.makechtec.web.authentication_gateway.asyn_http.HttpAsyncActionConfigurer;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationFilterConfigurer;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.makechtec.web.authentication_gateway.ioc.ManuallyInjectable;
import org.makechtec.web.authentication_gateway.password.PasswordHasher;
import org.makechtec.web.authentication_gateway.password.SaltGenerator;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper.iocContainer;

@RestController
@RequestMapping("user")
public class ExternalUserController implements ManuallyInjectable {

    private final HttpServletRequest request;
    private CommonResponseBuilder commonResponseBuilder;
    private RequestValidationFilterConfigurer requestValidationFilterConfigurer;
    private HttpAsyncActionConfigurer httpAsyncActionConfigurer;

    @Autowired
    public ExternalUserController(HttpServletRequest request) {
        this.request = request;
    }

    @Override
    public void inject() {

        this.commonResponseBuilder = (CommonResponseBuilder) iocContainer.getSingleton("commonResponseBuilder");
        this.requestValidationFilterConfigurer = (RequestValidationFilterConfigurer) iocContainer.getSingleton("requestValidationFilterConfigurer");
        this.httpAsyncActionConfigurer = (HttpAsyncActionConfigurer) iocContainer.getSingleton("httpAsyncActionConfigurer");

    }

    @PostMapping(
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> register(
            @RequestHeader("User-Agent") String clientAgent,
            @RequestHeader("Authorization") String authorization,

            @RequestBody String body
    ) {

        var token = authorization.replace("Bearer ", "").trim();

        var jsonBody = new JSONObject(body);

        var clientAddress = request.getRemoteAddr();

        var context = new EnvironmentContext();

        context.setItem("clientJWTToken", token);
        context.setItem("clientIP", clientAddress);
        context.setItem("clientAgent", clientAgent);
        context.setItem("clientRateLimitTitle", "external-user.client.register");
        context.setItem("externalUserIP", jsonBody.getString("externalUserIP"));
        context.setItem("externalUserAgent", jsonBody.getString("externalUserAgent"));
        context.setItem("externalUserCSRFToken", jsonBody.getString("externalUserCSRFToken"));
        context.setItem("externalUserRateLimitTitle", "external-user.external-user.register");
        context.setItem("externalUserUsername", jsonBody.getString("externalUserUsername"));
        context.setItem("externalUserPassword", jsonBody.getString("externalUserPassword"));
        context.setItem("externalUserRole", jsonBody.getString("externalUserRole"));


        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("externalUserControllerFilters", "register")
                        .stream()
                        .filter(validationFilter -> validationFilter.canPassRequest(context))
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
            return possiblyErrorResponse.get().responseEntity();
        }

        var possiblyErrorInAction =
                httpAsyncActionConfigurer.provideActions("externalUserControllerActions", "register")
                        .stream()
                        .parallel()
                        .peek(action -> action.perform(context))
                        .filter(action -> !action.hasSuccessfulFinished(context))
                        .map(action -> action.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorInAction.isPresent()) {
            return possiblyErrorInAction.get().responseEntity();
        }

        var jwtToken = (String) context.getItem("clientCredentialsAsyncFilter.jwtToken");

        var message =
                ObjectLeaftBuilder.builder()
                        .put("token", jwtToken)
                        .build();

        return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);
    }

}
