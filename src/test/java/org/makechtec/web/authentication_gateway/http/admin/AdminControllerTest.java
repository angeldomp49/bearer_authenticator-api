package org.makechtec.web.authentication_gateway.http.admin;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AdminControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    private RateLimiter rateLimiter;

    @MockBean
    private CSRFTokenHandler csrfTokenHandler;

    @BeforeEach
    void setUp() {
    }

    @Test
    void login() throws Exception {

        when(csrfTokenHandler.isValidCSRFToken(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        var requestBody = ObjectLeaftBuilder.builder()
                .put("username", "test")
                .put("password", "test")
                .build();

        mvc.perform(
                        post("/admin/login")
                                .header("User-Agent", "test")
                                .header("X-Csrf-Token", "test")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(requestBody.getLeafValue())
                )
                .andDo(print())
                .andExpect(status().isCreated())
                .andExpect(content().contentType(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.body.data").exists())
                .andExpect(jsonPath("$.statusCode").exists())
        ;

    }
}