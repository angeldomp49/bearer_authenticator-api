package org.makechtec.web.authentication_gateway.bearer.session;

import java.util.Calendar;
import java.util.List;

public record SessionInformation(
        Calendar expirationDate,
        boolean isClosed,
        long userId,
        List<String> permissions
) {
}
