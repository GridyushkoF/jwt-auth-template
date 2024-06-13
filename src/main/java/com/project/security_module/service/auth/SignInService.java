package com.project.security_module.service.auth;

import com.project.security_module.service.jwt.JwtUtils;
import com.project.security_module.service.user_details.UserDetailsImpl;
import com.project.security_module.web.request.SignInRequest;
import com.project.security_module.web.response.SignInResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class SignInService {
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    public SignInResponse signIn(SignInRequest signInRequest) {
        Authentication authentication = getAuthByLoginRequest(signInRequest);

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtUtils.generateJwtToken(authentication);
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());

        return new SignInResponse(jwt, userDetails.getId(), userDetails.getUsername(), userDetails.getEmail(), roles);
    }

    private Authentication getAuthByLoginRequest(SignInRequest signInRequest) {
        return authenticationManager.
                authenticate(new UsernamePasswordAuthenticationToken(
                        signInRequest.getUsername(), signInRequest.getPassword()));
    }
}
