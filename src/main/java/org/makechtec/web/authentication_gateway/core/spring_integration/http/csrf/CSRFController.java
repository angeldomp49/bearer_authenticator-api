package org.makechtec.web.authentication_gateway.core.spring_integration.http.csrf;

import jakarta.servlet.http.HttpServletRequest;
import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.commons.asyn_http.HttpAsyncActionConfigurer;
import org.makechtec.web.authentication_gateway.commons.filtering.RequestValidationFilterConfigurer;
import org.makechtec.web.authentication_gateway.commons.http.CommonResponseBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;


@RequestMapping("csrf")
public class CSRFController {

    private final RequestValidationFilterConfigurer requestValidationFilterConfigurer;
    private final HttpAsyncActionConfigurer httpAsyncActionConfigurer;
    private final CommonResponseBuilder responseBuilder;

    public CSRFController(RequestValidationFilterConfigurer requestValidationFilterConfigurer, HttpAsyncActionConfigurer httpAsyncActionConfigurer, CommonResponseBuilder responseBuilder) {
        this.requestValidationFilterConfigurer = requestValidationFilterConfigurer;
        this.httpAsyncActionConfigurer = httpAsyncActionConfigurer;
        this.responseBuilder = responseBuilder;
    }


    @PostMapping(
            value = "/client",
            produces = MediaType.APPLICATION_JSON_VALUE,
            consumes = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> generateCSRFTokenForClient(
            @RequestHeader("User-Agent") String userAgent,
            HttpServletRequest request
    ) {

        var userIP = request.getRemoteAddr();

        var context = new EnvironmentContext();

        context.setItem("clientRateLimitTitle", "csrf");
        context.setItem("clientIP", userIP);
        context.setItem("clientAgent", userAgent);

        var possiblyErrorResponse =
                requestValidationFilterConfigurer.provideFilters("csrfControllerFilters", "client")
                        .stream()
                        .parallel()
                        .filter(validationFilter -> !validationFilter.canPassRequest(context))
                        .map(requestValidationFilter -> requestValidationFilter.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorResponse.isPresent()) {
            return possiblyErrorResponse.get().responseEntity();
        }

        var possiblyErrorInAction =
                httpAsyncActionConfigurer.provideActions("csrfControllerActions", "client")
                        .stream()
                        .parallel()
                        .peek(action -> action.perform(context))
                        .filter(action -> !action.hasSuccessfulFinished(context))
                        .map(action -> action.createFailedResponse(context))
                        .findFirst();

        if (possiblyErrorInAction.isPresent()) {
            return possiblyErrorInAction.get().responseEntity();
        }

        var message =
                ObjectLeaftBuilder.builder()
                        .put("token", (String) context.getItem("csrfToken"))
                        .build();

        return new ResponseEntity<>(responseBuilder.createResponse(message, HttpStatus.CREATED), HttpStatus.CREATED);
    }

}
