package org.makechtec.web.authentication_gateway.http;

import org.junit.jupiter.api.Test;
import org.makechtec.web.authentication_gateway.bearer.BearerAuthenticationFactory;
import org.makechtec.web.authentication_gateway.bearer.JWTTokenHandler;
import org.makechtec.web.authentication_gateway.bearer.session.SessionGenerator;
import org.makechtec.web.authentication_gateway.bearer.user.UserAuthenticator;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.sql.SQLException;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AuthControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    private RateLimiter rateLimiter;

    @MockBean
    private CSRFTokenHandler csrfTokenHandler;

    @MockBean
    private BearerAuthenticationFactory bearerAuthenticationFactory;

    @Test
    void loginByUserRequest() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenHandler.isValidCSRFToken(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        var userAuthenticator = mock(UserAuthenticator.class);

        when(userAuthenticator.areValidCredentials(anyString(), anyString()))
                .thenReturn(true);

        when(bearerAuthenticationFactory.userAuthenticator()).thenReturn(userAuthenticator);

        when(bearerAuthenticationFactory.sessionGenerator()).thenReturn(mock(SessionGenerator.class));

        when(bearerAuthenticationFactory.jwtTokenHandler()).thenReturn(mock(JWTTokenHandler.class));

        mvc.perform(
                        post("/auth/login")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                                .header("X-Csrf-Token", "Bearer test")
                                .param("username", "test")
                                .param("password", "test")
                )
                .andDo(print())
                .andExpect(status().isCreated())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void loginByUserRequest_TooManyRequests() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(false);

        mvc.perform(
                        post("/auth/login")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                                .header("X-Csrf-Token", "Bearer test")
                                .param("username", "test")
                                .param("password", "test")
                )
                .andDo(print())
                .andExpect(status().isTooManyRequests())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;
    }

    @Test
    void loginByUserRequest_unauthorized() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenHandler.isValidCSRFToken(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(false);

        mvc.perform(
                        post("/auth/login")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                                .header("X-Csrf-Token", "Bearer test")
                                .param("username", "test")
                                .param("password", "test")
                )
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;
    }

    @Test
    void loginByUserRequest_unauthorizedInvalidCredentials() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        when(csrfTokenHandler.isValidCSRFToken(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        var userAuthenticator = mock(UserAuthenticator.class);

        when(userAuthenticator.areValidCredentials(anyString(), anyString()))
                .thenReturn(false);

        when(bearerAuthenticationFactory.userAuthenticator()).thenReturn(userAuthenticator);

        when(bearerAuthenticationFactory.sessionGenerator()).thenReturn(mock(SessionGenerator.class));

        when(bearerAuthenticationFactory.jwtTokenHandler()).thenReturn(mock(JWTTokenHandler.class));

        mvc.perform(
                        post("/auth/login")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                                .header("X-Csrf-Token", "Bearer test")
                                .param("username", "test")
                                .param("password", "test")
                )
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;
    }

    @Test
    void loginByUserRequest_sqlException() throws Exception {

        when(rateLimiter.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenThrow(new SQLException());

        mvc.perform(
                        post("/auth/login")
                                .header("User-Address", "127.0.0.1")
                                .header("User-Agent", "test")
                                .header("Client-Address", "127.0.0.1")
                                .header("X-Csrf-Token", "Bearer test")
                                .param("username", "test")
                                .param("password", "test")
                )
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void checkToken() throws Exception {

        var jwtTokenHandler = mock(JWTTokenHandler.class);

        when(jwtTokenHandler.isInBlackList(anyString())).thenReturn(false);

        when(jwtTokenHandler.isValidSignature(anyString())).thenReturn(true);

        when(bearerAuthenticationFactory.jwtTokenHandler()).thenReturn(jwtTokenHandler);

        mvc.perform(
                        get("/auth/check")
                                .header("Authorization", "Bearer test")
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void checkToken_isInBlackList() throws Exception {

        var jwtTokenHandler = mock(JWTTokenHandler.class);

        when(jwtTokenHandler.isInBlackList(anyString())).thenReturn(true);

        when(bearerAuthenticationFactory.jwtTokenHandler()).thenReturn(jwtTokenHandler);

        mvc.perform(
                        get("/auth/check")
                                .header("Authorization", "Bearer test")
                )
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void checkToken_isValidTokenFalse() throws Exception {

        var jwtTokenHandler = mock(JWTTokenHandler.class);

        when(jwtTokenHandler.isInBlackList(anyString())).thenReturn(false);

        when(jwtTokenHandler.isValidSignature(anyString())).thenReturn(false);

        when(bearerAuthenticationFactory.jwtTokenHandler()).thenReturn(jwtTokenHandler);

        mvc.perform(
                        get("/auth/check")
                                .header("Authorization", "Bearer test")
                )
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void checkToken_sqlException() throws Exception {

        var jwtTokenHandler = mock(JWTTokenHandler.class);

        when(jwtTokenHandler.isInBlackList(anyString())).thenThrow(new SQLException());

        when(bearerAuthenticationFactory.jwtTokenHandler()).thenReturn(jwtTokenHandler);

        mvc.perform(
                        get("/auth/check")
                                .header("Authorization", "Bearer test")
                )
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

    @Test
    void logout() throws Exception {

        var jwtTokenHandler = mock(JWTTokenHandler.class);

        doNothing().when(jwtTokenHandler).addToBlackList(anyString());

        when(bearerAuthenticationFactory.jwtTokenHandler()).thenReturn(jwtTokenHandler);

        mvc.perform(
                        delete("/auth/logout")
                                .header("Authorization", "Bearer test")
                )
                .andDo(print())
                .andExpect(status().isNoContent())
        ;

    }

    @Test
    void logout_sqlException() throws Exception {

        var jwtTokenHandler = mock(JWTTokenHandler.class);

        doThrow(new SQLException()).when(jwtTokenHandler).addToBlackList(anyString());

        when(bearerAuthenticationFactory.jwtTokenHandler()).thenReturn(jwtTokenHandler);

        mvc.perform(
                        delete("/auth/logout")
                                .header("Authorization", "Bearer test")
                )
                .andDo(print())
                .andExpect(status().isInternalServerError())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }

}