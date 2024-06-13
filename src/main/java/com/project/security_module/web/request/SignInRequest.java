package com.project.security_module.web.request;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
public @Data class SignInRequest {
    @NotBlank
    private String username;

    @NotBlank
    private String password;

}
