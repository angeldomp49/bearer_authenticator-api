package org.makechtec.web.authentication_gateway.filtering;

import org.springframework.http.ResponseEntity;

public record ValidationFailedResponse(
        ResponseEntity<String> responseEntity
) {
}
