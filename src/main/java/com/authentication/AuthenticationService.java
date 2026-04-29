package com.authentication;
import com.customer.Customer;
import com.customer.CustomerRepository;
import com.exception.UserAlreadyExistsException;
import com.secuirty.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;

@Service
public class AuthenticationService {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthenticationService(CustomerRepository customerRepository, PasswordEncoder passwordEncoder,
                                 JwtService jwtService, AuthenticationManager authenticationManager) {
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
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

    public ResponseCookie loginUser(LoginRequestDto loginRequest) {
        //Authenticate customer if exists
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.emailAddress(), loginRequest.password()));
        //Generate JWT token and return it as Http cookie
        String jwt = jwtService.createToken(loginRequest.emailAddress());
        return jwtService.issueJwtCookie("token", jwt, Duration.ofHours(1));
    }
}
