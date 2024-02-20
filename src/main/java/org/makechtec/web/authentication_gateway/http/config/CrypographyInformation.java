package org.makechtec.web.authentication_gateway.http.config;

import org.springframework.beans.factory.annotation.Value;

public class CrypographyInformation {

    @Value("${cryptography.secret-key}")
    private String secretKey;
    @Value("${cryptography.argon2.settings.memory-in-kb}")
    private int argon2SettingsMemory;
    @Value("${cryptography.argon2.settings.iterations}")
    private int argon2SettingsIterations;
    @Value("${cryptography.argon2.settings.parallelism-factor}")
    private int argon2SettingsParallelismFactor;

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public int getArgon2SettingsMemory() {
        return argon2SettingsMemory;
    }

    public void setArgon2SettingsMemory(int argon2SettingsMemory) {
        this.argon2SettingsMemory = argon2SettingsMemory;
    }

    public int getArgon2SettingsIterations() {
        return argon2SettingsIterations;
    }

    public void setArgon2SettingsIterations(int argon2SettingsIterations) {
        this.argon2SettingsIterations = argon2SettingsIterations;
    }

    public int getArgon2SettingsParallelismFactor() {
        return argon2SettingsParallelismFactor;
    }

    public void setArgon2SettingsParallelismFactor(int argon2SettingsParallelismFactor) {
        this.argon2SettingsParallelismFactor = argon2SettingsParallelismFactor;
    }
}
