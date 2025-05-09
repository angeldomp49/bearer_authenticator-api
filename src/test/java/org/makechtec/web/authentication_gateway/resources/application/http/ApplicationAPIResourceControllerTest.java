package org.makechtec.web.authentication_gateway.resources.application.http;

import org.junit.jupiter.api.Test;
import org.makechtec.bearer_authentication.tools.bearer.stateless.argon.PasswordHasherNative;
import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.validators.*;
import org.makechtec.web.authentication_gateway.resources.application.api.ApplicationDBConnection;
import org.makechtec.web.authentication_gateway.resources.application.api.ApplicationModel;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@WebMvcTest(ApplicationAPIResourceController.class)
class ApplicationAPIResourceControllerTest {

    private static final String URL_PREFIX = "/application/api";

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ControllerValidatorFactory validatorFactory;

    @MockBean
    private CommonJSONResponseBuilder responseBuilder;

    @MockBean
    private CacheSystemTable cacheSystemTable;

    @MockBean
    private PasswordHasherNative passwordHasherNative;

    @MockBean
    private ApplicationDBConnection applicationDBConnection;


    @Test
    void store() throws Exception {

        var inputs = new HashMap<String, Object>();

        inputs.put("hasAttemptsAvailable", true);
        inputs.put("token", "fake token");
        inputs.put("isValidIP", true);

        createValidatorFactory(inputs);

        when(passwordHasherNative.rawHashNotIncludingSalt(anyString(), any(byte[].class)))
                .thenReturn("fake string".getBytes());

        doNothing()
                .when(applicationDBConnection)
                .store(any(ApplicationModel.class));

        var expectedNodes = "$.body['data', 'statusCode']";
        var expectedMessageNode = "$.body.data.message";

        mockMvc.perform(
                        post(URL_PREFIX).header("Application-Agent", "Custom agent")
                                .header("Application-X-Csrf-Token", "csrf token")
                                .header("Application-Authorization", "Bearer sessionToken")
                                .param("accessKey", "accessKey")
                                .param("secret", "secret")
                ).andExpect(status().isCreated())
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

        var sessionAuthenticator = mock(ResourceSessionValidator.class);

        when(sessionAuthenticator.isValidJWTSignature(anyString()))
                .thenReturn((boolean) inputs.get("isValidIP"));


        when(validatorFactory.getCSRFValidator())
                .thenReturn(csrfValidator);

        when(validatorFactory.getIPBlackListValidator())
                .thenReturn(ipBlackListValidator);

        when(validatorFactory.getRateLimitValidator())
                .thenReturn(rateLimitValidator);

        when(validatorFactory.getSessionAuthenticator())
                .thenReturn(sessionAuthenticator);

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