package org.makechtec.web.authentication_gateway.http.admin;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.makechtec.software.json_tree.builders.ObjectLeaftBuilder;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper;
import org.makechtec.web.authentication_gateway.mock.ioc.BeansDefinitionMock;
import org.makechtec.web.authentication_gateway.mock.ioc.IOCContainerBootstraperMock;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimitTimeUnit;
import org.makechtec.web.authentication_gateway.rate_limit.RateLimiter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.event.ApplicationStartedEvent;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.makechtec.web.authentication_gateway.ioc.IOCContainerBootstraper.iocContainer;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import(IOCContainerBootstraperMock.class)
class AdminControllerTest {

    @Autowired
    private MockMvc mvc;

    @MockBean
    private IOCContainerBootstraper iocContainerBootstraper;

    @BeforeEach
    public void setup() {

    }

    @Test
    void login() throws Exception {

        var rateLimiterMock = (RateLimiter) iocContainer.getSingleton("rateLimiter");
        var csrfTokenHandlerMock = (CSRFTokenHandler) iocContainer.getSingleton("csrfTokenHandler");

        when(rateLimiterMock.hasAttemptsThisClient(anyString(), anyString(), anyString(), anyString()))
                .thenReturn(true);

        doNothing()
                .when(rateLimiterMock).registerNewRateLimit(anyString(), anyInt(), any(RateLimitTimeUnit.class), anyInt());

        when(csrfTokenHandlerMock.isValidCSRFToken(anyString(), anyString(), anyString(), anyString()))
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