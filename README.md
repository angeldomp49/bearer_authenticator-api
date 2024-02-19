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
    Authorization: Bearer eyJ0eXAiOiJqd3QiLCJhbGciOiJTSEEyNTYifQ==.eyJ1aWQiOjEsImlzQ2xvc2VkIjpmYWxzZSwicGVybWlzc2lvbnMiOlsicmVhZCIsInNob3cgb3duIGJpbGxzIiwid3JpdGUiLCJlZGl0IG93biBwcm9maWxlIl0sImV4cCI6MTcxMDk2NjE3MDMxN30=.d002fdd4bfae5c9ffbf762c8d6928ce20ef8422af94c695376d27975c73cc560
    ###
    
    ### DELETE Logout
    DELETE {{hostname}}/auth/logout
    Authorization: Bearer eyJ0eXAiOiJqd3QiLCJhbGciOiJTSEEyNTYifQ==.eyJ1aWQiOjEsImlzQ2xvc2VkIjpmYWxzZSwicGVybWlzc2lvbnMiOlsicmVhZCIsInNob3cgb3duIGJpbGxzIiwid3JpdGUiLCJlZGl0IG93biBwcm9maWxlIl0sImV4cCI6MTcxMDk2NjE3MDMxN30=.d002fdd4bfae5c9ffbf762c8d6928ce20ef8422af94c695376d27975c73cc560
    ###

As you can see, the login receives username and associated password, for check and logout you may send the JWT token received in login response,
once you send to logout endpoint the token is blacklisted and you cannot use it again.


## CONFIGURATION ##

Indeed, the database model is in another repository, but also you should to provide connection credentials in application.properties file,
the application-example.properties is an example