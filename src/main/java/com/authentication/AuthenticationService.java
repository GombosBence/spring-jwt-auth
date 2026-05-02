package com.authentication;
import com.customer.Customer;
import com.customer.CustomerRepository;
import com.exception.UserAlreadyExistsException;
import com.google.common.hash.Hashing;
import com.secuirty.JwtService;
import com.secuirty.RefreshToken;
import com.secuirty.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
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

    public LoginResponseDto loginUser(LoginRequestDto loginRequest) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.emailAddress(), loginRequest.password()));
        Customer customer = customerRepository.findByEmailAddress(loginRequest.emailAddress()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        String refreshToken = generateRefreshToken(customer);
        String jwt = jwtService.createToken(loginRequest.emailAddress());
        return new LoginResponseDto(
                jwtService.issueResponseCookie("token", jwt, Duration.ofHours(1)),
                jwtService.issueResponseCookie("refreshToken", refreshToken, Duration.ofDays(7))
                );
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
