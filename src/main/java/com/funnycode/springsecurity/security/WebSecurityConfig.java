package com.funnycode.springsecurity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity //Bật tính năng web security lên
public class WebSecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder() { // Dùng để mã hóa mật khẩu với thuật toán Bcrypt
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService() { //Giả lập tạo 2 account: 1 USER và 1 ADMIN
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user")
                .password(passwordEncoder().encode("123"))
                .roles("USER")
                .build());

        manager.createUser(User.withUsername("admin")
                .password(passwordEncoder().encode("123"))
                .roles("ADMIN")
                .build());
        return manager;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {// Cấu hình security ở đây
        httpSecurity.authorizeRequests()
                .antMatchers("/", "/home").permitAll()//Với đường dẫn / , /home thì cho phép truy cập mà không cần đăng nhập
                .antMatchers("/admin/**").hasAnyRole("ADMIN") //Những request bắt đầu với admin/**, Chỉ role ADMIN mới có thể truy cập
                .anyRequest().authenticated() //Các quest còn lại đều yêu cầu đăng nhập
                .and()
                .formLogin() //Sử dụng form login mặc định của spring security
                .defaultSuccessUrl("/home") //Default khi đăng nhập thành công sẽ redirect đến /home
                .failureUrl("/login") //Khi đăng nhập thất bại sẽ redirect về trang login
                .permitAll() //Trang login có thể truy cập mà không cần đăng nhập
                .and()
                .logout()//Cho phép logout
                .permitAll();
        return httpSecurity.build();
    }
}
