package com.devblog.heolog.filter;


import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class Myfilter2 implements Filter{
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        // 토큰: hdh  이걸 만들어 줘야함 -> id, pw 정상적으로 들어와서 로그인이 완료돼면 토큰 만들어주고 그걸 응답을 해준다.
        // 그럼 요청할 때마다 header Authorization 에 value 값으로 토큰을 가지고 옴
        // 그때 가져오는 토큰이 내가 만든 토큰이 맞는지만 검증하면 됨 (RSA, HS256)
        if (req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("필터2");

            if (headerAuth.equals("hdh")) {
                chain.doFilter(request, response); // 끝나지 말고 계속 프로세스를 진행해라
            }
            else {

                PrintWriter out = res.getWriter();
                out.println("인증안됨");
            }
        }



    }
}
