package com.example.jwt.config;

import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)

                .and()
                .addFilter(corsFilter) // @CrosOrigin(인증x) 작동, 인증O 작동 필요 시 필터 등록
                .formLogin().disable()
                .httpBasic().disable()
                // 요청을 할 때마다 header - Authorization: 인증 정보(ID, PW)를 보내는 방식, 암호화x( https를 쓸 경우 암호화 )
                // -> JWT 토큰은 header - Authorization: 토큰, 노출이 되어도 인증 정보가 없기 때문에 그나마 안전, Bearer 방식
                .authorizeHttpRequests()
                .antMatchers("/api/v1/user/**")
                .hasAnyRole("ROLE_USER", "ROLE_MANAGE", "ROLE_ADMIN")
                .antMatchers("/api/v1/manage/**")
                .hasAnyRole("ROLE_MANAGE", "ROLE_ADMIN")
                .antMatchers("/api/v1/amin/**")
                .hasAnyRole("ROLE_ADMIN")
                .anyRequest().permitAll();


    }

}
