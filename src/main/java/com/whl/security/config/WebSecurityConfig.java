package com.whl.security.config;

import static org.springframework.security.config.Customizer.withDefaults;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.util.HashMap;


@Configuration //配置类
@EnableMethodSecurity
public class WebSecurityConfig {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    //开启授权保护
    http.authorizeHttpRequests(
          (authorize) -> authorize
//            .requestMatchers("/user/list").hasAuthority("USER_LIST")
//            .requestMatchers("/user/add").hasAuthority("USER_ADD")
            .requestMatchers("/user/**").hasRole("ADMIN")
          //对所有请求开启授权保护
          .anyRequest()
          //已认证的请求会被自动授权
          .authenticated()
    );
    //自动使用表单授权方式【注释后就没有html的登录页面了，就只有浏览器默认自带的】
    http.formLogin(form -> {
      form.loginPage("/login").permitAll()
        .usernameParameter("myusername")
        .passwordParameter("mypassword")
        .failureUrl("/login?error")//校验失败时跳转
        .successHandler(new MyAuthenticationSuccessHandler())//认证成功时的处理
        .failureHandler(new MyAuthenticationFailureHandler())//认证失败时的处理
      ;
    });

    http.logout(logout -> {
      logout.logoutSuccessHandler(new MyLogoutSuccessHandler()); //注销成功处理
    });

    http.exceptionHandling(exception -> {
      exception.authenticationEntryPoint(new MyAuthenticationEntryPoint()); //请求未认证处理
      exception.accessDeniedHandler(new MyAccessDeniedHandler());
    });

    //会话并发处理
    http.sessionManagement(session -> {
      session.maximumSessions(1).expiredSessionStrategy(new MySessionInformationExpiredStrategy());
    });

    //跨域
    http.cors(withDefaults());

    //关闭CSRF攻击防御
    http.csrf(csrf -> csrf.disable());

    return http.build();
  }

//  @Bean
//  public UserDetailsService userDetailsService() {
//    // 创建基于内存的用户信息管理器
//    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
//
//    //使用manager来管理UserDetails对象
//    manager.createUser(
//        //创建UserDetails对象，用户管理用户名、用户密码、用户角色、用户权限等内容
//        User.withDefaultPasswordEncoder()
//          .username("whl")
//          .password("password")
//          .roles("USER").build()
//    );
//
//    return manager;
//  }

//  @Bean
//  public UserDetailsService userDetailsService() {
//    // 创建基于数据库的用户信息管理器
//    DBUserDetailsManager manager = new DBUserDetailsManager();
//
//    return manager;
//  }
}
