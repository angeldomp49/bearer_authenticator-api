package org.makechtec.web.authentication_gateway.http.config;

import org.springframework.beans.factory.annotation.Value;

public class AuthenticationConnectionInformation {

    @Value("${authentication.connection-information.user}")
    private String user;
    @Value("${authentication.connection-information.password}")
    private String password;
    @Value("${authentication.connection-information.hostname}")
    private String hostname;
    @Value("${authentication.connection-information.database}")
    private String database;
    @Value("${authentication.connection-information.port}")
    private String port;

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getDatabase() {
        return database;
    }

    public void setDatabase(String database) {
        this.database = database;
    }

    public String getPort() {
        return port;
    }

    public void setPort(String port) {
        this.port = port;
    }
}
