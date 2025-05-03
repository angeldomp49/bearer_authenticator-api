package org.makechtec.web.authentication_gateway.commons.http;

import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.software.json_tree.builders.ObjectLeafBuilder;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

public class CommonJSONResponseBuilder {

    public String createResponse(ObjectLeaf content, HttpStatus status) {
        return
                ObjectLeafBuilder.builder()
                        .put("statusCode", status.value())
                        .put("body",
                                ObjectLeafBuilder.builder()
                                        .put("data",
                                                content
                                        )
                                        .build()
                        )
                        .build()
                        .getLeafValue();
    }

    public String createResponseWithMessage(String message, HttpStatus status) {
        return createResponse(
                ObjectLeafBuilder.builder()
                        .put("message", message)
                        .build(),
                status
        );
    }
    
    public ResponseEntity<String> createResponseWithStatus(HttpStatus status){
        return new ResponseEntity<>(
                createResponseWithMessage(
                        status.getReasonPhrase(),
                        status),
                status
        );
    }
    
}