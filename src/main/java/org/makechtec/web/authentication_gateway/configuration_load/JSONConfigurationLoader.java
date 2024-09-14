package org.makechtec.web.authentication_gateway.configuration_load;

import org.json.JSONObject;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

public class JSONConfigurationLoader {


    public JSONObject loadConfiguration(File configurationFile) {
        var filename = configurationFile.getName();

        try(var filterReferenceInputStream = new FileInputStream(configurationFile)){

            return new JSONObject(new String(filterReferenceInputStream.readAllBytes()));


        } catch (IOException e) {
            throw new RuntimeException("Configuration file not found for name: " + filename);
        }
    }

}
