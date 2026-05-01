package com.customer;

import com.secuirty.RefreshToken;
import jakarta.persistence.*;
import lombok.Data;

import java.util.List;
import java.util.UUID;

@Entity
@Data
@Table(name = "customer")
public class Customer {

    @Id
    @Column(name = "customer_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID customerId;

    @Column(name = "last_name")
    private String lastName;

    @Column(name = "first_name")
    private String firstName;

    @Column(name = "email_address")
    private String emailAddress;

    @Column(name = "customer_password")
    private String password;

    @OneToMany(mappedBy = "customer")
    private List<RefreshToken> refreshTokenList;


    public Customer(){}
    public Customer(String lastName, String firstName, String emailAddress, String password){
        this.lastName = lastName;
        this.firstName = firstName;
        this.emailAddress = emailAddress;
        this.password = password;
    }
}
