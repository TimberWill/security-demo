package com.whl.security.config;

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import org.springframework.security.web.session.SessionInformationExpiredEvent;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;

public class MySessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {

  /**
   * 当会话失效时的处理.
   *
   * @param event
   * @throws IOException
   * @throws ServletException
   */
  @Override
  public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException,
      ServletException {

    HashMap result = new HashMap();
    result.put("code", -1); //失败
    result.put("msg", "该账号已从其他设备登录");

    //将对象转为json字符串
    String json = JSON.toJSONString(result);

    //返回响应
    HttpServletResponse response = event.getResponse();
    response.setContentType("application/json;charset=UTF-8");
    response.getWriter().println(json);

  }
}
