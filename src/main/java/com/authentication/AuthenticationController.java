package com.authentication;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;

    @Autowired
    public AuthenticationController(AuthenticationService authenticationService){
        this.authenticationService = authenticationService;
    }

    @PostMapping("/register")
    public ResponseEntity<String> register(@Valid @RequestBody RegisterRequestDto registerRequest){
        authenticationService.registerUser(registerRequest);
        return ResponseEntity.ok().body("User successfully registered");
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@Valid @RequestBody LoginRequestDto loginRequest){
        CookieResponseDto response = authenticationService.loginUser(loginRequest);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, response.jwt().toString())
                .header(HttpHeaders.SET_COOKIE, response.refreshToken().toString())
                .body("Successful authentication");
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<String> refreshToken(@Valid HttpServletRequest request){
            CookieResponseDto response = authenticationService.getNewJwt(request);
            return ResponseEntity.ok()
                    .header(HttpHeaders.SET_COOKIE, response.jwt().toString())
                    .header(HttpHeaders.SET_COOKIE, response.refreshToken().toString())
                    .body("Token successfully refreshed");
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(@Valid HttpServletRequest request){
        CookieResponseDto response = authenticationService.logout(request);
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, response.jwt().toString())
                .header(HttpHeaders.SET_COOKIE, response.refreshToken().toString())
                .body("Successfully logged out");
    }
}
