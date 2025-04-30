package org.makechtec.web.authentication_gateway.commons.components.rate_limit;

public record RateLimitSchema(
        String schema,
        RateLimit rateLimit
) {
}
