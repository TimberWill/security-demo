package com.whl.security.config;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
  @Override
  public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

    String localizedMessage = exception.getLocalizedMessage();

    HashMap result = new HashMap();
    result.put("code", -1);
    result.put("msg", localizedMessage);

    //将对象转为json字符串
    String json = JSON.toJSONString(result);

    //认证成功后返回json数据
    response.setContentType("application/json;charset=UTF-8");
    response.getWriter().println(json);
  }
}
