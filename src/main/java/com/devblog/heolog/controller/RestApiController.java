package com.devblog.heolog.controller;

import com.devblog.heolog.auth.PrincipalDetails;
import com.devblog.heolog.model.User;
import com.devblog.heolog.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @GetMapping("/home")
    public String home() {
        System.out.println("클라이언트로부터 /home 요청");
        return "<h1>home</h1>";
    }

    @PostMapping("/token")
    public String token() {
        System.out.println("클라이언트로부터 /token 요청");
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);

        return "회원가입 완료";
    }

    // user , admin 권한
    @GetMapping("/api/user")
    public String user(Authentication authentication) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("authentication :" + principalDetails.getUsername());
        return "user";
    }

    // admin 권한
    @GetMapping("/api/admin")
    public String admin() {
        return "admin";
    }


}
