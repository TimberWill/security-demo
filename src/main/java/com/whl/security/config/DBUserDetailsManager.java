package com.whl.security.config;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.whl.security.entity.User;
import com.whl.security.mapper.UserMapper;
import jakarta.annotation.Resource;
import java.util.ArrayList;
import java.util.Collection;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

@Component
public class DBUserDetailsManager implements UserDetailsManager, UserDetailsPasswordService {

  //引入持久层
  @Resource
  private UserMapper userMapper;

  @Override
  public UserDetails updatePassword(UserDetails user, String newPassword) {
    return null;
  }

  /**
   * 向数据库中插入新的用户信息.
   *
   * @param userDetails 用户信息
   */
  @Override
  public void createUser(UserDetails userDetails) {
    //实现数据插入
    User user = new User();
    user.setUsername(userDetails.getUsername());
    user.setPassword(userDetails.getPassword());
    user.setEnabled(true);

    userMapper.insert(user);

  }

  @Override
  public void updateUser(UserDetails user) {

  }

  @Override
  public void deleteUser(String username) {

  }

  @Override
  public void changePassword(String oldPassword, String newPassword) {

  }

  @Override
  public boolean userExists(String username) {
    return false;
  }

  /**
   * 通过用户名从数据库中获取用户信息.
   *
   * @param username 用户名
   * @return UserDetails对象
   * @throws UsernameNotFoundException
   */
  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    QueryWrapper<User> queryWrapper = new QueryWrapper<>();
    queryWrapper.eq("username", username);
    User user = userMapper.selectOne(queryWrapper);
    if (user == null) {
      throw new UsernameNotFoundException(username);
    } else {
      /** Collection<GrantedAuthority> authorities = new ArrayList<>();
//      authorities.add(() -> "USER_LIST");
      authorities.add(() -> "USER_ADD");

      //组装security中的user对象
      return new org.springframework.security.core.userdetails.User(
          user.getUsername(),
          user.getPassword(),
          user.getEnabled(),
          true, //用户账号是否过期
          true, //用户凭证是否过期
          true, //用户是否未被锁定
          authorities //权限列表【暂时先创建空的】
      );*/

      return org.springframework.security.core.userdetails.User
        .withUsername(user.getUsername())
        .password(user.getPassword())
        .disabled(!user.getEnabled())
        .credentialsExpired(false)
        .accountLocked(false)
        .roles("ADMIN")
        .authorities("USER_ADD")
        .build();

    }

  }
}
