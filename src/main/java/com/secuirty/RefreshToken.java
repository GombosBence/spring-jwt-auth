package com.secuirty;

import com.customer.Customer;
import jakarta.persistence.*;
import lombok.Data;

import java.time.Instant;
import java.util.UUID;

@Entity
@Data
@Table(name = "refresh_token")
public class RefreshToken {

    @Id
    @Column(name = "token_id")
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID tokenId;

    @Column(name = "token_hash")
    private String hashedValue;

    @Column(name =  "expiration_date")
    private Instant expiryAt;

    @Column(name = "revoked")
    private boolean revoked;

    @ManyToOne
    @JoinColumn(name = "customer_id")
    private Customer customer;

    public RefreshToken(){}

    public RefreshToken(String value, Instant expiryAt, Customer customer){
        this.hashedValue = value;
        this.expiryAt = expiryAt;
        this.customer = customer;
        this.revoked = false;
    }
}
