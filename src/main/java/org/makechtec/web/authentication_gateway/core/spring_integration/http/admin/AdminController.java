package org.makechtec.web.authentication_gateway.core.spring_integration.http.admin;

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
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/admin")
public class AdminController {

    private final RequestValidationFilterConfigurer requestValidationFilterConfigurer;
    private final HttpAsyncActionConfigurer httpAsyncActionConfigurer;
    private final CommonResponseBuilder commonResponseBuilder;

    public AdminController(RequestValidationFilterConfigurer requestValidationFilterConfigurer, HttpAsyncActionConfigurer httpAsyncActionConfigurer, CommonResponseBuilder commonResponseBuilder) {
        this.requestValidationFilterConfigurer = requestValidationFilterConfigurer;
        this.httpAsyncActionConfigurer = httpAsyncActionConfigurer;
        this.commonResponseBuilder = commonResponseBuilder;
    }


    @PostMapping(
            value = "/login",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> login(
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,
            @RequestBody String body,
            HttpServletRequest request
    ) {

        var userIP = request.getRemoteAddr();
        var jsonBody = new JSONObject(body);

        var context = new EnvironmentContext();

        context.setItem("clientIP", userIP);
        context.setItem("clientAgent", userAgent);
        context.setItem("clientCSRFToken", xCsrfToken);
        context.setItem("clientUsername", jsonBody.getString("username"));
        context.setItem("clientPassword", jsonBody.getString("password"));
        context.setItem("clientRateLimitTitle", "login");

        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("adminControllerFilters", "login")
                        .stream()
                        .parallel()
                        .filter(validationFilter -> !validationFilter.canPassRequest(context))
                        .peek(System.out::println)
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .peek(System.out::println)
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
            System.err.println(possiblyErrorResponse.get().filterCause());
            return possiblyErrorResponse.get().responseEntity();
        }

        var possiblyErrorInAction =
                httpAsyncActionConfigurer.provideActions("adminControllerActions", "login")
                        .stream()
                        .parallel()
                        .peek(action -> action.perform(context))
                        .filter(action -> !action.hasSuccessfulFinished(context))
                        .map(action -> action.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorInAction.isPresent()) {

            return possiblyErrorInAction.get().responseEntity();
        }

        var jwtToken = (String) context.getItem("clientCredentialsAsyncFilter.jwtToke");

        var message =
                ObjectLeaftBuilder.builder()
                        .put("token", jwtToken)
                        .build();

        return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

    }


}
