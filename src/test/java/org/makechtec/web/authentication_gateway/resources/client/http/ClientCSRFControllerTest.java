package org.makechtec.web.authentication_gateway.resources.client.http;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@AutoConfigureMockMvc
@SpringBootTest
class ClientCSRFControllerTest {

    private static final String URL_PREFIX = "client/csrf";

    @Autowired
    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {

    }

    @Test
    void getCSRF() throws Exception {
        mockMvc.perform(
                MockMvcRequestBuilders.get(URL_PREFIX).header("Client-Agent", "Test browser")
                        .header("Client-Address", "127.1.0.0")
                        .header("Application-Authorization", "jwt")
        ).andExpect(status().isOk());
    }

}