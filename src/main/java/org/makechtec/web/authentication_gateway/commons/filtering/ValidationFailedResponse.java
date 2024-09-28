package org.makechtec.web.authentication_gateway.commons.filtering;

import org.springframework.http.ResponseEntity;

public record ValidationFailedResponse(
        ResponseEntity<String> responseEntity,
        String filterCause
) {
}
