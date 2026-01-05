package com.whl.security.controller;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexController {

  @GetMapping("/")
  public Map index() {
    SecurityContext context = SecurityContextHolder.getContext();
    Authentication authentication = context.getAuthentication();
    Object principal = authentication.getPrincipal();
    Object credentials = authentication.getCredentials(); //脱敏
    Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    String name = authentication.getName();

    HashMap result = new HashMap();
    result.put("username", name);
    result.put("authorities", authorities);

    return result;
  }
}
