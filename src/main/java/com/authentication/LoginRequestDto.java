package com.authentication;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequestDto(@NotBlank String emailAddress,@NotBlank @Size(min = 8) String password) {
}
