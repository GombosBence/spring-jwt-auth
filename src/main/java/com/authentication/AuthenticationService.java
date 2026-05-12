package com.authentication;
import com.customer.Customer;
import com.customer.CustomerRepository;
import com.exception.RefreshTokenExpiredException;
import com.exception.RefreshTokenNotFoundException;
import com.exception.UserAlreadyExistsException;
import com.google.common.hash.Hashing;
import com.secuirty.JwtService;
import com.secuirty.RefreshToken;
import com.secuirty.RefreshTokenRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthenticationService {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RefreshTokenRepository refreshTokenRepository;

    @Autowired
    public AuthenticationService(CustomerRepository customerRepository, PasswordEncoder passwordEncoder,
                                 JwtService jwtService, AuthenticationManager authenticationManager, RefreshTokenRepository refreshTokenRepository) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public void registerUser(RegisterRequestDto registerRequest) {
        //Check if customer already exists in db
        Optional<Customer> customerOptional = customerRepository.findByEmailAddress(registerRequest.emailAddress());
        if (customerOptional.isPresent()) throw new UserAlreadyExistsException(registerRequest.emailAddress());
        //Create new customer if not already in db
        String encryptedPassword = passwordEncoder.encode(registerRequest.password());
        Customer newCustomer = new Customer(registerRequest.lastName(), registerRequest.firstName(),
                registerRequest.emailAddress(), encryptedPassword);
        customerRepository.save(newCustomer);
    }

    public CookieResponseDto loginUser(LoginRequestDto loginRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.emailAddress(), loginRequest.password()));
        Customer customer = customerRepository.findByEmailAddress(loginRequest.emailAddress()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        String refreshToken = generateRefreshToken(customer);
        String jwt = jwtService.createToken(loginRequest.emailAddress());
        return new CookieResponseDto(
                jwtService.issueResponseCookie("token", jwt, Duration.ofHours(1)),
                jwtService.issueResponseCookie("refreshToken", refreshToken, Duration.ofDays(7))
                );
    }

    public CookieResponseDto getNewJwt(HttpServletRequest request){
        String refreshToken = getTokenFromCookie(request, "refreshToken");
        if(refreshToken == null) throw new RefreshTokenNotFoundException("RefreshToken not found in the request");
        RefreshToken dbToken = refreshTokenRepository.findByHashedValue(Hashing.sha256().hashString(refreshToken, StandardCharsets.UTF_8).toString())
                .orElseThrow(() -> new RefreshTokenNotFoundException("RefreshToken not found"));
        if(dbToken.getExpiryAt().isBefore(Instant.now()) || dbToken.isRevoked()) throw new RefreshTokenExpiredException("RefreshToken expired or revoked");

        dbToken.setRevoked(true);
        refreshTokenRepository.save(dbToken);
        String newRefreshToken = generateRefreshToken(dbToken.getCustomer());
        return new CookieResponseDto(
                jwtService.issueResponseCookie("token", jwtService.createToken(dbToken.getCustomer().getEmailAddress()), Duration.ofHours(1)),
                jwtService.issueResponseCookie("refreshToken", newRefreshToken, Duration.ofDays(7))
        );
    }

    public CookieResponseDto logout(HttpServletRequest request){
        String refreshToken = getTokenFromCookie(request, "refreshToken");
        if(refreshToken == null) throw new RefreshTokenNotFoundException("Refresh token not found in the request");
        RefreshToken dbToken = refreshTokenRepository.findByHashedValue(Hashing.sha256().hashString(refreshToken, StandardCharsets.UTF_8).toString())
                .orElseThrow(() -> new RefreshTokenNotFoundException("RefreshToken not found"));

        dbToken.setRevoked(true);
        refreshTokenRepository.save(dbToken);
        return new CookieResponseDto(
                jwtService.issueResponseCookie("token", "", Duration.ZERO),
                jwtService.issueResponseCookie("refreshToken", "", Duration.ZERO)
        );
    }


    private String getTokenFromCookie(HttpServletRequest request, String cookieName){
        if(request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> cookieName.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private String generateRefreshToken(Customer customer){
        String rawString = UUID.randomUUID().toString();
        String hashedString = Hashing.sha256().hashString(rawString, StandardCharsets.UTF_8).toString();
        refreshTokenRepository.save(new RefreshToken(
                hashedString,
                Instant.now().plus(Duration.ofDays(7)),
                customer
        ));
        return rawString;
    }
}
