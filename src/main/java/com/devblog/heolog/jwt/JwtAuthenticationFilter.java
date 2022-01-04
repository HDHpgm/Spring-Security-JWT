package com.devblog.heolog.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.devblog.heolog.auth.PrincipalDetails;
import com.devblog.heolog.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;

// 스프링 시큐리티에 UsernamePasswordAuthenticationFilter 가 있는데
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작함
// 지금은 시큐리티에서 form login 안쓴다고 했기 때문에 직접 필터 연결 해줘야함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    // 실행되는 함수 attemptAuthentication
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도");
        try {
            // 1. username, password 받아서
            ObjectMapper om = new ObjectMapper(); // json 데이터를 파싱해줌
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println(user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService 의 loadUserByUsername 실행된 후 정상이면 authentication이 리턴됨
            // 내 로그인한 정보가 담김 => DB에 있는 username 과 password 가 일치한다.

            // 2. 정상인지 로그인 시도 해보기 authenticationManager 로 로그인 시도하면
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            // 2-1. > PrincipalDetailsService 가 호출됨 > loadUserByUsername() 실행됨 > 정상이면 PrincipalDetails 리턴
            // => 아래가 된다면 로그인이 됐다는 뜻
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("로그인 완료 됨 : "+principalDetails.getUser().getUsername()); // 로그인 정상적으로 되었다는 뜻

            // 리턴될 때 authentication 객체가 session 영역에 저장됨
            // 리턴의 이유는 권한관리를 security 가 대신 해주기 때문에 편하려고 하는 것
            // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 근데 단지 권한 처리 때문에 넣어 줌
            return authentication;

        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수 실행됨
    // 여기서 JWT 토큰 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해줌
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨");
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
        String jwtToken = JWT.create()
                .withSubject(JwtProperties.SECRET)
                .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.EXPIRATION_TIME)) // 만료시간 = 현재시간 + 10분
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512(JwtProperties.SECRET)); // RSA 아니고 HASH 암호 방식, 서버만 알고있는 키 가지고 있어야 함

        response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
    }
}
