package org.makechtec.web.authentication_gateway.integration;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.concordion.api.ConcordionFixture;
import org.concordion.api.FullOGNL;
import org.makechtec.web.authentication_gateway.AuthApiApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.util.Map;

@ConcordionFixture
@FullOGNL
public class ApplicationLoginFluxTestFixture {

    private static final String BASE_URL = "http://localhost:";
    private static final int PORT = 8080;
    
    public String csrfPath;
    public String sessionLoginPath;
    public String sessionCheckPath;

    private final TestRestTemplate restTemplate = new TestRestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    public void startServer() {
        SpringApplication.run(AuthApiApplication.class);
    }

    public String getCSRFToken(Map<String, String> headersMap) throws JsonProcessingException {
        
        var headers = new HttpHeaders();
        
        headersMap.forEach(headers::set);
        
        var request = new HttpEntity<>("", headers);
        
        return restTemplate.exchange(fullURI(csrfPath), HttpMethod.GET, request, String.class)
                .getBody();
        
    }
    
    public CSRFResponse csrfResponseFromJson(String jsonString) throws JsonProcessingException {
        var jsonBody = objectMapper.readTree(jsonString);
        
        return new CSRFResponse(
                jsonBody.get("body").get("data").get("token").asText(),
                jsonBody.get("statusCode").asInt()
        );
    }
    
    public record CSRFResponse(
            String token,
            int statusCode
    ){}
    
    public String sessionLogin(Map<String, String> headersMap, MultiValueMap<String, String> requestParamsMap){

        var headers = new HttpHeaders();

        headersMap.forEach(headers::set);
        

        var request = new HttpEntity<>(requestParamsMap, headers);
        
        return restTemplate.postForEntity(fullURI(sessionLoginPath), request, String.class)
                .getBody();
        
    }
    
    public SessionLoginResponse sessionLoginResponseFromJson(String jsonString) throws JsonProcessingException {
        var jsonBody = objectMapper.readTree(jsonString);
        
        return new SessionLoginResponse(
                jsonBody.get("body").get("data").get("token").asText(),
                jsonBody.get("statusCode").asInt() 
        );
    }
    
    public record SessionLoginResponse(
            String token,
            int statusCode
    ){}

    public String sessionCheck(Map<String, String> headersMap){

        var headers = new HttpHeaders();

        headersMap.forEach(headers::set);


        var request = new HttpEntity<>("", headers);

        return restTemplate.exchange(fullURI(sessionCheckPath), HttpMethod.GET, request, String.class)
                .getBody();

    }

    public SessionCheckResponse sessionCheckResponseFromJson(String jsonString) throws JsonProcessingException {
        var jsonBody = objectMapper.readTree(jsonString);

        return new SessionCheckResponse(
                jsonBody.get("body").get("data").get("isValid").asBoolean(),
                jsonBody.get("statusCode").asInt()
        );
    }
    
    public record SessionCheckResponse(
            boolean isValid,
            int statusCode
    ){}
    
    public URI fullURI(String path){
        return URI.create(BASE_URL + PORT + path);
    }

    public void setCsrfPath(String csrfPath) {
        this.csrfPath = csrfPath;
    }

    public void setSessionLoginPath(String sessionLoginPath) {
        this.sessionLoginPath = sessionLoginPath;
    }

    public void setSessionCheckPath(String sessionCheckPath) {
        this.sessionCheckPath = sessionCheckPath;
    }
    
}
