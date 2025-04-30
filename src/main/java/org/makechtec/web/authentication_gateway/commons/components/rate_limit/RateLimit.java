package org.makechtec.web.authentication_gateway.commons.components.rate_limit;

public record RateLimit(String title, int attempts, String unit, int timeQuantity) {
}
