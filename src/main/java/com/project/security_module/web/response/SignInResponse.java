package com.project.security_module.web.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
@Data
@AllArgsConstructor
@NoArgsConstructor
public class SignInResponse {
  private String token;
  private final String type = "Bearer";
  private Long id;
  private String username;
  private String email;
  private List<String> roles;
}
