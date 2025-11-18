package com.whl.security.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.whl.security.config.DBUserDetailsManager;
import com.whl.security.entity.User;
import com.whl.security.mapper.UserMapper;
import com.whl.security.service.UserService;
import jakarta.annotation.Resource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

  @Resource
  public DBUserDetailsManager dbUserDetailsManager;

  @Override
  public void saveUserDetails(User user) {

    UserDetails userDetails = org.springframework.security.core.userdetails.User
        .withDefaultPasswordEncoder()
        .username(user.getUsername())
        .password(user.getPassword())
        .roles("USER").build();
    dbUserDetailsManager.createUser(userDetails);
  }
}
