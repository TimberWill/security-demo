package com.whl.security.controller;

import com.whl.security.entity.User;
import com.whl.security.service.UserService;
import jakarta.annotation.Resource;
import java.util.List;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {
  @Resource
  public UserService userService;

  /**
   * 获取用户列表.
   *
   * @return
   */
  @PreAuthorize("hasRole('ADMIN') and authentication.name == 'admin'")
  @GetMapping("/list")
  public List<User> getList() {
    return userService.list();
  }

  /**
   * 添加用户.
   *
   * @param user 用户信息
   * @return
   */
//  @PreAuthorize("hasRole('ADMIN')")
  @PreAuthorize("hasAuthority('USER_ADD')")
  @PostMapping("/add")
  public void add(@RequestBody User user) {
    userService.saveUserDetails(user);
  }

}
