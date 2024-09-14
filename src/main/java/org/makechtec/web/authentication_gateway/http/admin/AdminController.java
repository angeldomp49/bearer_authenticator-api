package org.makechtec.web.authentication_gateway.http.admin;

import jakarta.servlet.http.HttpServletRequest;
import org.json.JSONObject;
import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.asyn_http.HttpAsyncActionConfigurer;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationFilterConfigurer;
import org.makechtec.web.authentication_gateway.http.commons.CommonResponseBuilder;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    public AdminController(RequestValidationFilterConfigurer requestValidationFilterConfigurer, HttpAsyncActionConfigurer httpAsyncActionConfigurer, CommonResponseBuilder commonResponseBuilder) {
        this.requestValidationFilterConfigurer = requestValidationFilterConfigurer;
        this.httpAsyncActionConfigurer = httpAsyncActionConfigurer;
        this.commonResponseBuilder = commonResponseBuilder;
    }

    @PostMapping(value = "/login", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<String> login(
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("X-Csrf-Token") String xCsrfToken,
            @RequestBody String body,
            HttpServletRequest request
    ) {

        var userIP = request.getRemoteAddr();
        var jsonBody = new JSONObject(body);

        var context = new EnvironmentContext();

        context.setItem("userIP", userIP);
        context.setItem("userAgent", userAgent);
        context.setItem("csrfToken", xCsrfToken);
        context.setItem("username", jsonBody.getString("username"));
        context.setItem("password", jsonBody.getString("password"));
        context.setItem("rateLimitTitle", "login");

        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("adminControllerFilters", "login")
                        .stream()
                        .parallel()
                        .filter(validationFilter -> !validationFilter.canPassRequest(context))
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
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

        var jwtToken = (String) context.getItem("jwtToken");

        var message =
                ObjectLeaftBuilder.builder()
                        .put("token", jwtToken)
                        .build();

        return new ResponseEntity<>(commonResponseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);

    }


}
