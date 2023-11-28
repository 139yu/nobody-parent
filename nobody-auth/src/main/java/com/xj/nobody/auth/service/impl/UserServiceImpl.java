package com.xj.nobody.auth.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.xj.nobody.auth.service.UserService;
import com.xj.nobody.auth.study.auth.entity.User;
import com.xj.nobody.auth.study.auth.mapper.UserMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.annotation.Resource;

//@Service
public class UserServiceImpl extends UserService {

    @Resource
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return userMapper.selectOne(Wrappers.lambdaQuery(User.class).eq(User::getUsername, s));
    }

    @Override
    public UserDetails updatePassword(UserDetails user, String newPassword) {
        int i = userMapper.updatePassowrd(user.getUsername(),newPassword);
        User u = (User) user;
        u.setPassword(newPassword);
        return user;
    }
}
