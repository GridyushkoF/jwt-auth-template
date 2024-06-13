package com.project.security_module.service.auth;

import com.project.security_module.exceptions.IncorrectSignUpDataException;
import com.project.security_module.models.User;
import com.project.security_module.repository.UserRepository;
import com.project.security_module.web.request.SignUpRequest;
import com.project.security_module.web.response.SignUpResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class SignUpService {
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    public SignUpResponse signUp(SignUpRequest signUpRequest) throws IncorrectSignUpDataException {
        throwExceptionIfRequestDataTaken(signUpRequest);
        initAndSaveNewUser(signUpRequest);
        return (new SignUpResponse("User registered successfully!"));
    }

    private void initAndSaveNewUser(SignUpRequest signUpRequest) {
        User user = new User(signUpRequest.getUsername(), signUpRequest.getEmail(), encoder.encode(signUpRequest.getPassword()));
        user.setRoles(signUpRequest.getRoles());
        userRepository.save(user);
    }

    private void throwExceptionIfRequestDataTaken(SignUpRequest signUpRequest) throws IncorrectSignUpDataException {
        if (userRepository.existsByUsername(signUpRequest.getUsername()) || userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new IncorrectSignUpDataException(new SignUpResponse("Username or email there is now!"));
        }
    }
}
