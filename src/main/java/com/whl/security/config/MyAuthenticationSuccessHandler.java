package com.whl.security.config;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.HashMap;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {
    //获取用户身份信息
    Object principal = authentication.getPrincipal();
//    //获取用户凭证信息
//    Object credentials = authentication.getCredentials();
//    //获取用户权限信息
//    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

    HashMap result = new HashMap();
    result.put("code", 0);
    result.put("msg", "登录成功");
    result.put("data", principal);

    //将对象转为json字符串
    String json = JSON.toJSONString(result);

    //认证成功后返回json数据
    response.setContentType("application/json;charset=UTF-8");
    response.getWriter().println(json);

  }
}
