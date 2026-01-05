package com.whl.security.config;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

public class MyLogoutSuccessHandler implements LogoutSuccessHandler {
  @Override
  public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                              Authentication authentication) throws IOException, ServletException {

    HashMap result = new HashMap();
    result.put("code", 0);//成功
    result.put("msg", "注销成功");

    //将对象转为json字符串
    String json = JSON.toJSONString(result);

    //认证成功后返回json数据
    response.setContentType("application/json;charset=UTF-8");
    response.getWriter().println(json);
  }
}
