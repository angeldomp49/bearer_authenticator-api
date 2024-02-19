package org.makechtec.web.authentication_gateway.bearer;

import org.makechtec.software.json_tree.builders.ArrayStringLeafBuilder;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.postgres.PostgresEngine;
import org.makechtec.software.sql_support.query_process.statement.ParamType;
import org.makechtec.web.authentication_gateway.bearer.session.SessionInformation;
import org.makechtec.web.authentication_gateway.bearer.token.SignaturePrinter;
import org.makechtec.web.authentication_gateway.bearer.token.TokenBuilder;

import java.sql.SQLException;
import java.util.logging.Logger;

public class JWTTokenHandler {

    public static final String SECRET_KEY = "secretKey";
    private static final Logger LOG = Logger.getLogger(JWTTokenHandler.class.getName());
    private final SignaturePrinter signaturePrinter = new SignaturePrinter();
    private final ConnectionInformation connectionInformation;

    public JWTTokenHandler(ConnectionInformation connectionInformation) {
        this.connectionInformation = connectionInformation;
    }

    public String createTokenForSession(SessionInformation session) {

        var permissionsSet = ArrayStringLeafBuilder.builder();

        session.permissions().forEach(permissionsSet::add);

        return TokenBuilder.builder()
                .header(
                        ObjectLeaftBuilder.builder()
                                .put("alg", "SHA256")
                                .put("typ", "jwt")
                                .build()
                )
                .payload(
                        ObjectLeaftBuilder.builder()
                                .put("exp", session.expirationDate().getTimeInMillis())
                                .put("uid", session.userId())
                                .put("isClosed", session.isClosed())
                                .put("permissions", permissionsSet.build())
                                .build()
                )
                .sign(SECRET_KEY)
                .build();
    }

    public boolean isValidSignature(String token) {
        var components = token.split("\\.");

        var message = components[0] + '.' + components[1] + '.' + SECRET_KEY;

        var reformedSignature = signaturePrinter.sign(message);
        var reformedToken = components[0] + '.' + components[1] + '.' + reformedSignature;

        System.out.println("old: " + token);
        System.out.println("reformed: " + reformedToken);

        return reformedToken.equals(token);
    }

    public boolean isInBlackList(String token) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            return
                    new PostgresEngine<Boolean>(connectionInformation)
                            .queryString("""
                                    SELECT COUNT(*) AS qty
                                    FROM atepoztli__authentication_service__schema.token_blacklist
                                    WHERE token = ?;
                                     """)
                            .isPrepared()
                            .addParamAtPosition(1, token, ParamType.TYPE_STRING)
                            .run(resultSet -> {
                                resultSet.next();

                                return resultSet.getLong("qty") > 0;
                            });

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem getting token blacklist");
            throw e;
        }
    }

    public void addToBlackList(String token) throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        try {
            new PostgresEngine<Boolean>(connectionInformation)
                    .queryString("""
                            INSERT INTO atepoztli__authentication_service__schema.token_blacklist (token)
                            VALUES(?);
                             """)
                    .isPrepared()
                    .addParamAtPosition(1, token, ParamType.TYPE_STRING)
                    .update();

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            LOG.severe("There was a problem putting token in blacklist");
            throw e;
        }
    }

}
