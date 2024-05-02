package org.makechtec.web.authentication_gateway.rate_limit;

public record RateLimit(int attempts, String unit, int timeQuantity) {
}
