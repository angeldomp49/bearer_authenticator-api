package org.makechtec.web.authentication_gateway.sql_tests;

import org.makechtec.software.sql_support.ConnectionInformation;
import org.makechtec.software.sql_support.connection_pool.postgres.PostgresPooledConnectionCreator;

public class SQLConfiguration {

    public static final ConnectionInformation SQL_CONNECTION = new ConnectionInformation(
            "postgres",
            "root",
            "localhost",
            "5432",
            "base_database"
    );

    public static final PostgresPooledConnectionCreator POSTGRES_POOLED_CONNECTION_CREATOR = new PostgresPooledConnectionCreator(SQL_CONNECTION);

}
