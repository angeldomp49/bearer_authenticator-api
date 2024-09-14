package org.makechtec.web.authentication_gateway.asyn_http;

import org.springframework.http.ResponseEntity;

public record FailedAsyncActionResponse(
        ResponseEntity<String> responseEntity
) {
}
