package com.project.security_module.controller;

import com.project.security_module.exceptions.IncorrectSignUpDataException;
import com.project.security_module.service.auth.SignInService;
import com.project.security_module.service.auth.SignUpService;
import com.project.security_module.web.request.SignInRequest;
import com.project.security_module.web.request.SignUpRequest;
import com.project.security_module.web.response.SignInResponse;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("${app.jwtSettings.securityApiAccountPrefix}")
@RequiredArgsConstructor
public class AccountController {

    private final SignInService signInService;
    private final SignUpService signUpService;

    @PostMapping("/sign-in")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody SignInRequest signInRequest,
                                              HttpServletResponse response) {
        SignInResponse signInResponse = signInService.signIn(signInRequest);
        String tokenValue = signInResponse.getType() + " " + signInResponse.getToken();
        String encodedToken = Base64.getEncoder().encodeToString(tokenValue.getBytes());
        Cookie authCookie = new Cookie("Authorization", encodedToken);
        authCookie.setHttpOnly(true);
        authCookie.setPath("/");
        response.addCookie(authCookie);
        return ResponseEntity.ok().body(signInResponse);
    }

    @PostMapping("/sign-up")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignUpRequest signUpRequest) {
        try {
            return ResponseEntity.ok(signUpService.signUp(signUpRequest));
        } catch (IncorrectSignUpDataException e) {
            return ResponseEntity.badRequest().body(e.getSignUpResponse());
        }
    }
}
