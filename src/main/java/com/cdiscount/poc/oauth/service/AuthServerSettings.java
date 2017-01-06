package com.cdiscount.poc.oauth.service;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "custom.auth-server")
public class AuthServerSettings {

    private String username;
    private String password;
    private String jwtEndpoint;

    String getUsername() {
        return username;
    }

    String getPassword() {
        return password;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    String getJwtEndpoint() {
        return jwtEndpoint;
    }

    public void setJwtEndpoint(String jwtEndpoint) {
        this.jwtEndpoint = jwtEndpoint;
    }
}