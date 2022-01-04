package com.devblog.heolog.config;

import com.devblog.heolog.jwt.JwtAuthenticationFilter;
import com.devblog.heolog.jwt.JwtAuthorizationFilter;
import com.devblog.heolog.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 시큐리티 동작 전에 토큰을 이용해 걸러내기 위한 필터 걸어놓음
//        http.addFilterBefore(new Myfilter2(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // 세션사용 x
        .and()
        .addFilter(corsFilter) // @CrossOrigin(인증이 필요없을때사용) / 있을때는 시큐리티 필터에 등록
        .formLogin().disable()
        .httpBasic().disable() // Bearer 방식 사용 (토큰)
        .addFilter(new JwtAuthenticationFilter(authenticationManager())) // AuthenticationManager 파라미터
                // 로그인을 진행하는 필터기 때문에 매니저를 전달해줘야함
        .addFilter(new JwtAuthorizationFilter(authenticationManager(), userRepository)) // AuthenticationManager 파라미터
        .authorizeRequests()
        .antMatchers("/api/user/**")
        .access("hasRole('ROLE_USER') or hasRole('ROLE_ADMIN')")
        .antMatchers("/api/admin/**")
        .access("hasRole('ROLE_ADMIN')")
        .anyRequest().permitAll();
    }
}
