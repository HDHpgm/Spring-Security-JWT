package com.devblog.heolog.filter;


import javax.servlet.*;
import java.io.IOException;

public class Myfilter1 implements Filter{
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("필터1");
        chain.doFilter(request, response); // 끝나지 말고 계속 프로세스를 진행해라
    }
}
