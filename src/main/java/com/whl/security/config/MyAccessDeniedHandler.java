package com.whl.security.config;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

public class MyAccessDeniedHandler implements AccessDeniedHandler {
  @Override
  public void handle(HttpServletRequest request, HttpServletResponse response,
                     AccessDeniedException accessDeniedException) throws IOException,
      ServletException {

    HashMap result = new HashMap();
    result.put("code", -1); //失败
    result.put("msg", "没有权限");

    //将对象转为json字符串
    String json = JSON.toJSONString(result);

    //认证成功后返回json数据
    response.setContentType("application/json;charset=UTF-8");
    response.getWriter().println(json);
  }
}
