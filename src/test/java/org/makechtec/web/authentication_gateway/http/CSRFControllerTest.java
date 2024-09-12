package org.makechtec.web.authentication_gateway.http;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenGenerator;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.SQLException;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ExtendWith(SpringExtension.class)
class CSRFControllerTest {

    @Autowired
    private MockMvc mvc;
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private CSRFController csrfController;

    @MockBean
    private RateLimiter rateLimiter;

    @MockBean
    private CSRFTokenGenerator csrfTokenGenerator;

    @MockBean
    private ClientValidator clientValidator;

    @MockBean
    private CSRFTokenHandler csrfTokenHandler;

    @BeforeEach
    void setUp() {
    }

    @Test
    void generateCSRFTokenForClient() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenGenerator.generateCSRFToken())
                .thenReturn("test");

        when(clientValidator.isAllowedClient(anyString()))
                .thenReturn(true);


        mockMvc.perform(
                post("/csrf/client/public")
                        .header("User-Address", "127.0.0.1")
                        .header("User-Agent", "test")
                        .header("Client-Address", "127.0.0.1")
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body").exists())
                .andExpect(jsonPath("$.statusCode").exists())
                ;

    }

    @Test
    void generateCSRFTokenForClient_hasAttemptsFalse() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(false);

        when(csrfTokenGenerator.generateCSRFToken())
                .thenReturn("test");

        when(clientValidator.isAllowedClient(anyString()))
                .thenReturn(true);


        mockMvc.perform(
                        post("/csrf/client/public")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                )
                .andDo(print())
                .andExpect(status().isTooManyRequests())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void generateCSRFTokenForClient_clientNotAllowed() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenGenerator.generateCSRFToken())
                .thenReturn("test");

        when(clientValidator.isAllowedClient(anyString()))
                .thenReturn(false);


        mockMvc.perform(
                        post("/csrf/client/public")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                )
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void generateCSRFTokenForClient_hasAttemptsThisClient_sqlException() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new SQLException());

        when(csrfTokenGenerator.generateCSRFToken())
                .thenReturn("test");

        when(clientValidator.isAllowedClient(anyString()))
                .thenReturn(true);


        mockMvc.perform(
                        post("/csrf/client/public")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                )
                .andDo(print())
                .andExpect(status().isTooManyRequests())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void generateCSRFTokenForClient_isAllowedClient_sqlException() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenGenerator.generateCSRFToken())
                .thenReturn("test");

        when(clientValidator.isAllowedClient(anyString()))
                .thenThrow(new SQLException());


        mockMvc.perform(
                        post("/csrf/client/public")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                )
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void generateCSRFTokenForClient_isAllowedClient_nullPointerException() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenGenerator.generateCSRFToken())
                .thenReturn("test");

        when(clientValidator.isAllowedClient(anyString()))
                .thenThrow(new NullPointerException());

        mockMvc.perform(
                        post("/csrf/client/public")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                )
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void generateCSRFTokenForClient_pushAttemptClient_sqlException() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenGenerator.generateCSRFToken())
                .thenReturn("test");

        when(clientValidator.isAllowedClient(anyString()))
                .thenReturn(true);

        doThrow(new SQLException())
                .when(rateLimiter).pushAttemptToThisClient(anyString(), anyString(), anyString());

        mockMvc.perform(
                        post("/csrf/client/public")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body").exists())
                .andExpect(jsonPath("$.statusCode").exists())
                ;

        assertFalse(csrfController.isHaveSuccededAllServices());


    }

    @Test
    void generateCSRFTokenForClient_registerCSRFToken_sqlException() throws Exception {

        doThrow(new SQLException())
                .when(csrfTokenHandler).registerCSRFToken(anyString(), anyString(), anyString(), anyLong(), anyString());

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenGenerator.generateCSRFToken())
                .thenReturn("test");

        when(clientValidator.isAllowedClient(anyString()))
                .thenReturn(true);



        mockMvc.perform(
                        post("/csrf/client/public")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

        assertFalse(csrfController.isHaveSuccededAllServices());


    }

}