package com.whl.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration //配置类
public class WebSecurityConfig {
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    //开启授权保护
    http.authorizeHttpRequests(
          (authorize) -> authorize
          //对所有请求开启授权保护
          .anyRequest()
          //已认证的请求会被自动授权
          .authenticated()
        )
        //自动使用表单授权方式【注释后就没有html的登录页面了，就只有浏览器默认自带的】
        .formLogin(form -> {
          form.loginPage("/login").permitAll()
            .usernameParameter("myusername")
            .passwordParameter("mypassword")
            .failureUrl("/login?error")//校验失败时跳转
          ;
        });
        //基本授权方式
        //.httpBasic(Customizer.withDefaults());

    //关闭CSRF攻击防御
//    http.csrf(csrf -> csrf.disable());

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
