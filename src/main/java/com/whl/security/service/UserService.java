package com.whl.security.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.whl.security.entity.User;

public interface UserService extends IService<User> {
  void saveUserDetails(User user);
}
