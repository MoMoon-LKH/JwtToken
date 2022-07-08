package com.example.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.jwt.auth.PrincipalDetails;
import com.example.jwt.entity.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.util.Date;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @SneakyThrows
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        
        // 1. username, pw 받아서
        
        /*BufferedReader br = request.getReader();

        String input = null;
        while ((input = br.readLine()) != null) {

        }
*/
        ObjectMapper om = new ObjectMapper();
        User user = om.readValue(request.getInputStream(), User.class);

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

        //2. 정상인지 로그인 시도를 해봄, authenticationManager 로 로그인 시도를 하면 PrincipalDetailsService가 호출
        // PrincipalDetailsService의 loadUsername() 함수가 실행됨
        //3. PrincipalDetails를 세션에 담고 (권한 관리를 위해)

        Authentication authentication =
                authenticationManager.authenticate(token);

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("principalDetails = " + principalDetails.getUser());
        // authentication 객체가 session 영역에 저장해야하고 그 방법이 return
        // 리턴의 이유는 권한 관리를 security가 대신 해주기때문에 편하게 하기 위해
        // 굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없다. 근데 단지 권한 처리때문에 session에 넣어줌

        
        //4. JWT 토큰 발행 및 응답
        
        return authentication;
    }

    // attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수가 실행
    // JWT를 만들어서 request 요청한 사용ㅇ자에게 JWT 토큰을 response 해주면 됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // Hash 암호방식
        String jwtToken = JWT.create()
                .withSubject(principalDetails.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("usernaem", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("jwtSample"));

        response.addHeader("Authorization", "Bearer " + jwtToken);

    }
}
