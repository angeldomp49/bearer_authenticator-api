package org.makechtec.web.authentication_gateway.rate_limit;

public enum RateLimitTimeUnit {

    DAY("DAY"),
    HOUR("HOUR"),
    MINUTE("MINUTE"),
    SECOND("SECOND");

    private final String name;

    private RateLimitTimeUnit(String name){
        this.name = name;
    }

    public String getName() {
        return name;
    }
}
