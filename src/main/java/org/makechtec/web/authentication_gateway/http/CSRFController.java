package org.makechtec.web.authentication_gateway.http;

import org.json.JSONObject;
import org.makechtec.web.authentication_gateway.csrf.CSRFTokenHandler;
import org.makechtec.web.authentication_gateway.csrf.ClientValidator;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.sql.SQLException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;

@RestController
@RequestMapping("csrf")
public class CSRFController {

    private final ClientValidator clientValidator;
    private final CSRFTokenHandler csrfTokenHandler;

    public CSRFController(ClientValidator clientValidator, CSRFTokenHandler csrfTokenHandler) {
        this.clientValidator = clientValidator;
        this.csrfTokenHandler = csrfTokenHandler;
    }

    @PostMapping("/client/public")
    public ResponseEntity<String> generateCSRFTokenForClient(
            @RequestHeader("User-Address") String userAddress,
            @RequestHeader("User-Agent") String userAgent,
            @RequestHeader("Client-Address") String clientAddress
    ) {
        try {

            if(!this.clientValidator.isAllowedClient(clientAddress)){
                return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
            }

            var expirationDate = Calendar.getInstance();

            expirationDate.add(Calendar.MINUTE, 30);

            var token = this.csrfTokenHandler.registerCSRFToken(userAddress,userAgent, clientAddress, expirationDate.getTimeInMillis());

            return new ResponseEntity<>(token, HttpStatus.OK);

        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException e) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }



}
