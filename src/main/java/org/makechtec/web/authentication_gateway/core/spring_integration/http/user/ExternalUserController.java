package org.makechtec.web.authentication_gateway.core.spring_integration.http.user;

import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.commons.asyn_http.HttpAsyncActionConfigurer;
import org.makechtec.web.authentication_gateway.commons.filtering.RequestValidationFilterConfigurer;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;


@RequestMapping("user")
public class ExternalUserController {

    private final CommonResponseBuilder commonResponseBuilder;
    private final RequestValidationFilterConfigurer requestValidationFilterConfigurer;
    private final HttpAsyncActionConfigurer httpAsyncActionConfigurer;

    public ExternalUserController(CommonResponseBuilder commonResponseBuilder, RequestValidationFilterConfigurer requestValidationFilterConfigurer, HttpAsyncActionConfigurer httpAsyncActionConfigurer) {
        this.commonResponseBuilder = commonResponseBuilder;
        this.requestValidationFilterConfigurer = requestValidationFilterConfigurer;
        this.httpAsyncActionConfigurer = httpAsyncActionConfigurer;
    }

    @PostMapping(
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> register(
            @RequestHeader("User-Agent") String clientAgent,
            @RequestHeader("Authorization") String authorization,

            @RequestBody String body,
            HttpServletRequest request
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
