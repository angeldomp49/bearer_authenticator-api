package org.makechtec.web.authentication_gateway.asyn_http;

import org.json.JSONArray;
import org.json.JSONObject;
import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.configuration_load.JSONConfigurationLoader;
import org.makechtec.web.authentication_gateway.filtering.RequestValidationFilterConfigurer;
import org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Controller;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Controller
public class HttpAsyncActionConfigurer implements ApplicationListener<ApplicationReadyEvent> {


    public static final String HTTP_ASYNC_ACTION_REFERENCE_JSON = "reference";
    public static final String HTTP_ASYNC_ACTION_CONFIGURATION_DIRECTORY = "http-action-configuration";
    public static final String HTTP_ASYNC_ACTION_CONFIGURATION_JSON_SUFFIX = "HttpAsyncActionConfigurationJSON";
    private static final String HTTP_ASYNC_ACTION_REFERENCE_FILENAME = "httpAsyncActionReference.json";

    public Set<HttpAsyncAction> provideActions(final String presetFilename, final String actionName) {

        if (presetFilename.isBlank()) {
            throw new IllegalArgumentException("PresetFilename cannot be blank");
        }

        var sanitizedConfigurationJSON = presetFilename.trim().replace(".json", "") + HTTP_ASYNC_ACTION_CONFIGURATION_JSON_SUFFIX;

        var jsonContent = (JSONObject) IOCContainerBootstraper.globalContext.getItem(sanitizedConfigurationJSON);

        var actions = new HashSet<HttpAsyncAction>();

        JSONArray jsonFilterList = jsonContent.getJSONArray(actionName.trim());

        for (int i = 0; i < jsonFilterList.length(); i++) {

            var beanId = jsonFilterList.getString(i);

            var scope = findJsonObjectByBeanId(beanId).getString("scope");

            if (scope.trim().equals("singleton")) {
                actions.add(
                        (HttpAsyncAction) IOCContainerBootstraper.iocContainer.getSingleton(beanId)
                );
            } else {
                actions.add(
                        (HttpAsyncAction) IOCContainerBootstraper.iocContainer.getPrototype(beanId)
                );
            }

        }

        return actions;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        loadAllConfigurationFiles(IOCContainerBootstraper.globalContext);
    }

    private void loadAllConfigurationFiles(EnvironmentContext context) {

        var referenceFileURL = RequestValidationFilterConfigurer.class.getClassLoader().getResource(HTTP_ASYNC_ACTION_REFERENCE_FILENAME);

        if (Objects.isNull(referenceFileURL)) {
            throw new RuntimeException("Reference file not found for the name: " + HTTP_ASYNC_ACTION_REFERENCE_FILENAME);
        }

        var referenceFile = new File(referenceFileURL.getFile());

        var jsonConfigurationLoader = (JSONConfigurationLoader) IOCContainerBootstraper.iocContainer.getSingleton("jsonConfigurationLoader");
        var jsonConfiguration = jsonConfigurationLoader.loadConfiguration(referenceFile);

        context.setItem(HTTP_ASYNC_ACTION_REFERENCE_FILENAME.replace(".json", "") + HTTP_ASYNC_ACTION_CONFIGURATION_JSON_SUFFIX, jsonConfiguration);

        var filterDirectoryURL = RequestValidationFilterConfigurer.class.getClassLoader().getResource(HTTP_ASYNC_ACTION_CONFIGURATION_DIRECTORY);

        var dirNonExists = Objects.isNull(filterDirectoryURL);

        if (dirNonExists) {
            return;
        }

        var filterDirectory = new File(filterDirectoryURL.getFile());

        if (Objects.isNull(filterDirectory.listFiles())) {
            return;
        }

        Arrays.stream(filterDirectory.listFiles())
                .forEach(file -> {
                    var jsonContent = jsonConfigurationLoader.loadConfiguration(file);
                    context.setItem(file.getName().replace(".json", "") + HTTP_ASYNC_ACTION_CONFIGURATION_JSON_SUFFIX, jsonContent);
                });

    }

    private JSONObject findJsonObjectByBeanId(String beanId) {
        var actionReferenceJson = (JSONObject) IOCContainerBootstraper.globalContext.getItem(HTTP_ASYNC_ACTION_REFERENCE_FILENAME.replace(".json", "") + HTTP_ASYNC_ACTION_CONFIGURATION_JSON_SUFFIX);

        JSONArray filters = actionReferenceJson.getJSONArray("actions");

        for (int i = 0; i < filters.length(); i++) {
            var filterObject = filters.getJSONObject(i);

            if (filterObject.getString("beanId").equals(beanId)) {
                return filterObject;
            }
        }

        throw new RuntimeException("There is not an action with specified bean id in the http action reference file the action searched was: " + beanId);
    }
}
