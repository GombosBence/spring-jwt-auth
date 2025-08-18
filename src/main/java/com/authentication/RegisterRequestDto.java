package com.authentication;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequestDto(@NotBlank String lastName, @NotBlank String firstName, @Email String emailAddress,
                                 @NotBlank @Size(min = 8) String password) {}
