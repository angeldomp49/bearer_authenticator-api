## REQUIREMENTS ##

- Java 17+
- Postgres

## USAGE ##

These are the three allowed actions to use the API

    @hostname = http://localhost:8080
    
    ### POST Login
    POST {{hostname}}/auth/login
    Content-Type: application/x-www-form-urlencoded
    
    username = angeldomp49 &
    password = 123
    ###
    
    ### GET Check
    GET {{hostname}}/auth/check
    Authorization: Bearer {{token}}
    ###
    
    ### DELETE Logout
    DELETE {{hostname}}/auth/logout
    Authorization: Bearer {{token}}
    ###

    ### POST register
    POST {{hostname}}/user
    Authorization: Bearer {{token}}
    Content-Type: application/x-www-form-urlencoded
    
    username = angel &
    email = angeldomp49@gmail.com &
    password = yupi2
    ###

As you can see, the login receives username and associated password, for check and logout you may send the JWT token received in login response,
once you send to logout endpoint the token is blacklisted and you cannot use it again.

For login this is the expected response:

    {
        "statusCode": 200,
        "body": {
            "data": {
                "token": //jwt token used to get authenticated for example in registration or check
            }
        }
    }


## CONFIGURATION ##

Indeed, the database model is in another repository, but also you should to provide connection credentials in application.properties file,
the application-example.properties is an example