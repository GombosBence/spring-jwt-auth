package com.customer;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;

@Service
public class CustomerInfoService implements UserDetailsService {

    private final CustomerRepository customerRepository;

    @Autowired
    public CustomerInfoService(CustomerRepository customerRepository){
        this.customerRepository = customerRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Customer> customer = customerRepository.findByEmailAddress(username);
        if(customer.isEmpty()) throw new UsernameNotFoundException("Username not found");

        Customer existingCustomer = customer.get();
        return new User(existingCustomer.getEmailAddress(), existingCustomer.getPassword(), Collections.emptyList());
    }
}
