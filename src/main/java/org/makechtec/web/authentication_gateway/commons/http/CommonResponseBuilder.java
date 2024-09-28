package org.makechtec.web.authentication_gateway.commons.http;

import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.commons.filtering.ValidationFailedResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class CommonResponseBuilder {

    public String createResponse(ObjectLeaf content, HttpStatus status) {
        return
                ObjectLeaftBuilder.builder()
                        .put("statusCode", status.value())
                        .put("body",
                                ObjectLeaftBuilder.builder()
                                        .put("data",
                                                content
                                        )
                                        .build()
                        )
                        .build()
                        .getLeafValue();
    }

    public ValidationFailedResponse createErrorResponse(String message, HttpStatus status, Class<?> sourceFilterClass) {
        var message1 =
                ObjectLeaftBuilder.builder()
                        .put("message", message)
                        .build();

        return new ValidationFailedResponse(
                new ResponseEntity<>(createResponse(message1, status), status),
                sourceFilterClass.getName()
        );
    }

    public ValidationFailedResponse createDatabaseErrorResponse(String message, Class<?> sourceFilterClass) {
        return createErrorResponse(message, HttpStatus.INTERNAL_SERVER_ERROR, sourceFilterClass);
    }

}