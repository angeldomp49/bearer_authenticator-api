package org.makechtec.web.authentication_gateway.filtering;

import org.json.JSONArray;
import org.json.JSONObject;
import org.makechtec.software.ioc_container.env.EnvironmentContext;
import org.makechtec.web.authentication_gateway.configuration_load.JSONConfigurationLoader;
import org.makechtec.web.authentication_gateway.ioc.OnStartUpListener;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Component
public class RequestValidationFilterConfigurer implements ApplicationListener<ApplicationReadyEvent> {

    private static final String FILTER_REFERENCE_FILENAME = "filterReference.json";
    public static final String FILTER_REFERENCE_JSON = "reference";
    public static final String FILTER_CONFIGURATION_DIRECTORY = "filter-configuration";
    public static final String FILTER_CONFIGURATION_JSON_SUFFIX = "FilterConfigurationJSON";

    public Set<RequestValidationAsyncFilter> provideFilters(final String presetFilename, final String actionName){

        if(presetFilename.isBlank()){
            throw new IllegalArgumentException("PresetFilename cannot be blank");
        }

        var sanitizedConfigurationJSON = presetFilename.trim().replace(".json", "") + FILTER_CONFIGURATION_JSON_SUFFIX;

        var jsonContent = (JSONObject) OnStartUpListener.globalContext.getItem(sanitizedConfigurationJSON);

        var filters = new HashSet<RequestValidationAsyncFilter>();

        JSONArray jsonFilterList = jsonContent.getJSONArray(actionName.trim());

        for(int i = 0; i < jsonFilterList.length(); i++){

            var beanId = jsonFilterList.getString(i);

            var scope = findJsonObjectByBeanId(beanId).getString("scope");

            if(scope.trim().equals("singleton")){
                filters.add(
                        (RequestValidationAsyncFilter) OnStartUpListener.iocContainer.getSingleton(beanId)
                );
            }
            else{
                filters.add(
                        (RequestValidationAsyncFilter) OnStartUpListener.iocContainer.getPrototype(beanId)
                );
            }

        }

        return filters;
    }

    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        loadAllFilterConfigurationFiles(OnStartUpListener.globalContext);
    }

    private void loadAllFilterConfigurationFiles(EnvironmentContext context){

        var referenceFileURL = RequestValidationFilterConfigurer.class.getClassLoader().getResource(FILTER_REFERENCE_FILENAME);

        if(Objects.isNull(referenceFileURL)){
            throw new RuntimeException("Reference file not found for the name: " + FILTER_REFERENCE_FILENAME);
        }

        var referenceFile = new File(referenceFileURL.getFile());

        var jsonConfigurationLoader = (JSONConfigurationLoader) OnStartUpListener.iocContainer.getSingleton("jsonConfigurationLoader");
        var jsonConfiguration = jsonConfigurationLoader.loadConfiguration(referenceFile);

        context.setItem(FILTER_REFERENCE_FILENAME + FILTER_CONFIGURATION_JSON_SUFFIX, jsonConfiguration);

        var filterDirectoryURL = RequestValidationFilterConfigurer.class.getClassLoader().getResource(FILTER_CONFIGURATION_DIRECTORY);

        var dirNonExists = Objects.isNull(filterDirectoryURL);

        if(dirNonExists){
            return;
        }

        var filterDirectory = new File(filterDirectoryURL.getFile());

        if(Objects.isNull(filterDirectory.listFiles())){
            return;
        }

        Arrays.stream(filterDirectory.listFiles())
                .forEach(file -> {
                    var jsonContent = jsonConfigurationLoader.loadConfiguration(file);
                    context.setItem(file.getName() + FILTER_CONFIGURATION_JSON_SUFFIX, jsonContent);
                });

    }

    private JSONObject findJsonObjectByBeanId(String beanId){
        var filterReferenceJson = (JSONObject) OnStartUpListener.globalContext.getItem(FILTER_REFERENCE_JSON);

        JSONArray filters = filterReferenceJson.getJSONArray("filters");

        for(int i = 0; i < filters.length(); i++){
            var filterObject = filters.getJSONObject(i);

            if(filterObject.getString("beanId").equals(beanId)){
                return filterObject;
            }
        }

        throw new RuntimeException("There is not a filter with specified bean id in the filter reference file the filter searched was: " + beanId);
    }

}
