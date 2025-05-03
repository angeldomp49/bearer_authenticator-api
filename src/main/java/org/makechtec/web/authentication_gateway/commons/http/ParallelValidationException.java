package org.makechtec.web.authentication_gateway.commons.http;

import org.springframework.http.ResponseEntity;

import java.util.concurrent.CompletionException;

public class ParallelValidationException extends CompletionException {
  
    private final ResponseEntity<String> response;
  
    public ParallelValidationException(Throwable throwable, ResponseEntity<String> response) {
        super(throwable);
        this.response = response;
    }

  public ParallelValidationException(ResponseEntity<String> response) {
    this.response = response;
  }

  public ResponseEntity<String> getResponse() {
      return response;
    }
  
}
