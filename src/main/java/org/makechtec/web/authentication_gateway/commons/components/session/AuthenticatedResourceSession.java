package org.makechtec.web.authentication_gateway.commons.components.session;

import org.makechtec.bearer_authentication.tools.bearer.stateless.token.SessionInformation;

public record AuthenticatedResourceSession(
        SessionInformation sessionInformation,
        long sessionId,
        long resourceId,
        String resourceJsonInformation
) {
}
