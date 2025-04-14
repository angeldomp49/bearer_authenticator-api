package org.makechtec.web.authentication_gateway.validation.rate_limit;

public record RateLimit(int attempts, String unit, int timeQuantity) {
}
