package org.makechtec.web.authentication_gateway.resources.application.http;

import net.bytebuddy.description.type.TypeDefinition;
import org.junit.jupiter.api.Test;
import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.validators.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@WebMvcTest(ApplicationCSRFController.class)
class ApplicationCSRFControllerTest {

    private static final String URL_PREFIX = "/application/csrf";

    @Autowired
    private MockMvc mockMvc;
    
    @MockBean
    private ControllerValidatorFactory validatorFactory;
    
    @MockBean
    private CommonJSONResponseBuilder responseBuilder;
    
    @MockBean
    private CacheSystemTable cacheSystemTable;
    
    @Test
    void getCSRFToken() throws Exception {

        var inputs = new HashMap<String, Object>();

        inputs.put("hasAttemptsAvailable", true);
        inputs.put("token", "fake token");
        inputs.put("isValidIP", true);
        
        createValidatorFactory(inputs);

        var expectedNodes = "$.body['data', 'statusCode']";
        var expectedTokenNode = "$.body.data.token";
        
        mockMvc.perform(
                get(URL_PREFIX).header("Application-Agent", "Custom agent")
        ).andExpect(status().isOk())
                .andExpect(jsonPath(expectedNodes).exists())
                .andExpect(jsonPath(expectedTokenNode).exists());
    }
    
    @Test
    void getCSRFTokenNoAttemptsAvailable() throws Exception {
        
        var inputs = new HashMap<String, Object>();
        
        inputs.put("hasAttemptsAvailable", false);
        inputs.put("token", "fake token");
        inputs.put("isValidIP", true);

        createValidatorFactory(inputs);

        var expectedNodes = "$.body['data', 'statusCode']";
        var expectedMessageNode = "$.body.data.message";

        mockMvc.perform(
                        get(URL_PREFIX).header("Application-Agent", "Custom agent")
                ).andExpect(status().isTooManyRequests())
                .andExpect(jsonPath(expectedNodes).exists())
                .andExpect(jsonPath(expectedMessageNode).exists());
        
    }


    @Test
    void getCSRFTokenInvalidIP() throws Exception {

        var inputs = new HashMap<String, Object>();

        inputs.put("hasAttemptsAvailable", true);
        inputs.put("token", "fake token");
        inputs.put("isValidIP", false);
        
        createValidatorFactory(inputs);

        var expectedNodes = "$.body['data', 'statusCode']";
        var expectedMessageNode = "$.body.data.message";

        mockMvc.perform(
                        get(URL_PREFIX).header("Application-Agent", "Custom agent")
                ).andExpect(status().isUnauthorized())
                .andExpect(jsonPath(expectedNodes).exists())
                .andExpect(jsonPath(expectedMessageNode).exists());
    }
    
    @Test
    void getCSRFTokenControllerValidationException() throws Exception {

        var inputs = new HashMap<String, Object>();

        inputs.put("hasAttemptsAvailable", true);
        inputs.put("token", "fake token");
        inputs.put("isValidIP", true);

        createValidatorFactory(inputs);

        var rateLimitValidator = mock(RateLimitValidator.class);

        doThrow(new ControllerValidationException(""))
                .when(rateLimitValidator)
                .hasAttemptsAvailable(anyMap(), anyString());

        when(validatorFactory.getRateLimitValidator())
                .thenReturn(rateLimitValidator);

        var expectedNodes = "$.body['data', 'statusCode']";
        var expectedMessageNode = "$.body.data.message";

        mockMvc.perform(
                        get(URL_PREFIX).header("Application-Agent", "Custom agent")
                ).andExpect(status().isInternalServerError())
                .andExpect(jsonPath(expectedNodes).exists())
                .andExpect(jsonPath(expectedMessageNode).exists());
    }
    
    private void createValidatorFactory(Map<String, Object> inputs) {

        var rateLimitValidator = mock(RateLimitValidator.class);

        when(rateLimitValidator.hasAttemptsAvailable(anyMap(), anyString()))
                .thenReturn((boolean) inputs.get("hasAttemptsAvailable"));

        doNothing()
                .when(rateLimitValidator)
                .sumOneAttempt(anyMap(), anyString());

        var csrfValidator = mock(CSRFValidator.class);

        when(csrfValidator.generateCSRFToken(anyString()))
                .thenReturn((String) inputs.get("token"));

        var ipBlackListValidator = mock(IPBlackListValidator.class);

        when(ipBlackListValidator.isValidIP(anyString(), anyString()))
                .thenReturn((boolean) inputs.get("isValidIP"));
        
        
        when(validatorFactory.getCSRFValidator())
                .thenReturn(csrfValidator);

        when(validatorFactory.getIPBlackListValidator())
                .thenReturn(ipBlackListValidator);

        when(validatorFactory.getRateLimitValidator())
                .thenReturn(rateLimitValidator);

        when(cacheSystemTable.request("temporaryApplicationSecretKey"))
                .thenReturn("tempSecretKey");

        when(responseBuilder.createResponse(any(ObjectLeaf.class), any(HttpStatus.class)))
                .thenCallRealMethod();
        
        when(responseBuilder.createResponseWithMessage(anyString(), any(HttpStatus.class)))
                .thenCallRealMethod();
        
        when(responseBuilder.createResponseWithStatus(any(HttpStatus.class)))
                .thenCallRealMethod();
        
    }
    
}