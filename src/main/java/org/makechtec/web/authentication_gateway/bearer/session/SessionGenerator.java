package org.makechtec.web.authentication_gateway.bearer.session;

import java.util.ArrayList;
import java.util.Calendar;

public class SessionGenerator {

    public SessionInformation createForUser(String username) {
        return new SessionInformation(Calendar.getInstance(), false, 1, new ArrayList<>());
    }

}
