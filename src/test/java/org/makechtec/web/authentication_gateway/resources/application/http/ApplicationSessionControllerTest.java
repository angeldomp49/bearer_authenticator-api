package org.makechtec.web.authentication_gateway.resources.application.http;

import org.junit.jupiter.api.Test;
import org.makechtec.software.json_tree.ObjectLeaf;
import org.makechtec.web.authentication_gateway.commons.components.cache.CacheSystemTable;
import org.makechtec.web.authentication_gateway.commons.http.CommonJSONResponseBuilder;
import org.makechtec.web.authentication_gateway.commons.http.validators.ControllerValidatorFactory;
import org.makechtec.web.authentication_gateway.commons.http.validators.ResourceSessionValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@WebMvcTest(ApplicationSessionController.class)
class ApplicationSessionControllerTest {

    private static final String URL_PREFIX = "/application/session";

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private ControllerValidatorFactory controllerValidatorFactory;

    @MockBean
    private CommonJSONResponseBuilder responseBuilder;

    @MockBean
    private CacheSystemTable cacheSystemTable;


    @Test
    void loginByUserRequest() {
    }

    @Test
    void checkToken() throws Exception {

        when(responseBuilder.createResponse(any(ObjectLeaf.class), any(HttpStatus.class)))
                .thenCallRealMethod();

        final var sessionValidator = mock(ResourceSessionValidator.class);

        when(sessionValidator.isValidJWTSignature(anyString())).thenReturn(true);

        when(controllerValidatorFactory.getSessionAuthenticator()).thenReturn(sessionValidator);

        var expectedNodes = "$.body['data', 'statusCode']";
        var expectedMessageNode = "$.body.data.isValid";

        mockMvc.perform(
                        get(URL_PREFIX + "/check").header("Application-Authorization", "Bearer fakeToken")
                ).andExpect(status().isOk())
                .andExpect(jsonPath(expectedNodes).exists())
                .andExpect(jsonPath(expectedMessageNode).exists());
    }

}