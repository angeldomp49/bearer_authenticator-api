package org.makechtec.web.authentication_gateway.plugins.bearer.session;

import java.util.Calendar;
import java.util.List;

public record SessionInformation(
        Calendar expirationDate,
        boolean isClosed,
        long userId,
        List<String> permissions
) {
}
