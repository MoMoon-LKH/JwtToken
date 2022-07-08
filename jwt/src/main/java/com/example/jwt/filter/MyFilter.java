package com.example.jwt.filter;


import org.springframework.security.core.parameters.P;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String headerAuth = req.getHeader("Authorization");

        // 토큰: cos를 만들어줘야됨, id,pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답
        // 요청할 때마다 header에 Authorization에 value 값으로 토큰을 가지고 옴
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰인지 검증이 필요 (RSA, HS256)
        if (req.getMethod().equals("POST")) {

            if (headerAuth.equals("cos")) {
                chain.doFilter(req,res);
            } else{
                PrintWriter outs = res.getWriter();
                outs.println("인증 안됨");
            }
        }

    }
}
