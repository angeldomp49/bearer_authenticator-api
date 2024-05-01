package org.makechtec.web.authentication_gateway.http.commons;

import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.springframework.http.HttpStatus;

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
}