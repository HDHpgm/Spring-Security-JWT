package com.devblog.heolog.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    // 얘를 필터에 등록해줘야함
    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); // 내 서버가 응답을 할 때 json 을 자바스크립트에서 처리할 수 있게 할지를 설정
        config.addAllowedOriginPattern("*"); // 모든 ip에 응답을 허용
        config.addAllowedHeader("*"); // 모든 header 에 응답을 허용
        config.addAllowedMethod("*"); // 모든 post, get , put ,delete, fetch 요청을 허용
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }

}
