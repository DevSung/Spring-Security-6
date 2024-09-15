package com.example.springsecurity6.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity // 스프링 시큐리티 안에서 사용하겠다는 의미
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder(); // 비밀번호 암호화
    }

    /**
     * ROLE_C를 가진 사용자는 ROLE_B와 ROLE_A의 권한도 모두 갖는다.
     * ROLE_B를 가진 사용자는 ROLE_A의 권한을 갖는다.
     * ROLE_A는 가장 하위 권한
     */
    @Bean
    public RoleHierarchy roleHierarchy() {

        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();

        hierarchy.setHierarchy("ROLE_C > ROLE_B\n" +
                "ROLE_B > ROLE_A");

        return hierarchy;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http // 순서가 중요 (permitAll 다음에 조건 처리가 중요하다)
                .authorizeHttpRequests(auth -> auth // 특정한 경로를 허용하거나 거부할 수 있다.
                        .requestMatchers("/login").permitAll()
                        .requestMatchers("/").hasRole("A")
                        .requestMatchers("/manager").hasRole("B")
                        .requestMatchers("/admin").hasRole("C")
                        .anyRequest().authenticated()  // 나머지경로 처리 authenticated (로그인한 회원만 접근 가능)
                );

        http
                .httpBasic(Customizer.withDefaults());

        http
                .csrf(auth -> auth.disable());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {

        UserDetails user1 = User.builder()
                .username("user1")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("C")
                .build();

        UserDetails user2 = User.builder()
                .username("user2")
                .password(bCryptPasswordEncoder().encode("1234"))
                .roles("A")
                .build();

        return new InMemoryUserDetailsManager(user1, user2);
    }

}
