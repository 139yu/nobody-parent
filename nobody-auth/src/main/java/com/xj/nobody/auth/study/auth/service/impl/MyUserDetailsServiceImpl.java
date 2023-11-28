package com.xj.nobody.auth.study.auth.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.xj.nobody.auth.study.auth.mapper.UserMapper;
import com.xj.nobody.auth.study.auth.entity.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

//@Service
public class MyUserDetailsServiceImpl implements UserDetailsService {

    @Resource
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        List<User> users = userMapper.selectList(Wrappers.lambdaQuery(User.class).eq(User::getUsername, username));
        if (users != null && users.size() > 0) {
            return users.get(0);
        }
        throw new UsernameNotFoundException("用户不存在!");
    }
}
