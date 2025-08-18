package com.authentication;
import com.customer.Customer;
import com.customer.CustomerRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthenticationService {

    private final CustomerRepository customerRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public AuthenticationService(CustomerRepository customerRepository, PasswordEncoder passwordEncoder){
        this.customerRepository = customerRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public boolean registerUser(RegisterRequestDto registerRequest){
        //Check if customer already exists in db
        Optional<Customer> customerOptional = customerRepository.findByEmailAddress(registerRequest.emailAddress());
        if(customerOptional.isPresent()) return false;
        //Create new customer if not already in db
        String encryptedPassword = passwordEncoder.encode(registerRequest.password());
        Customer newCustomer = new Customer(registerRequest.lastName(), registerRequest.firstName(),
                registerRequest.emailAddress(), encryptedPassword);
        customerRepository.save(newCustomer);
        return true;
    }
}
