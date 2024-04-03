package com.xj.nobody.auth.service;

import com.xj.nobody.auth.feign.AdminFeignClient;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserServiceImpl implements UserDetailsService {
    @Autowired
    private AdminFeignClient adminFeignClient;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserDTO userDTO = adminFeignClient.loadUserByUsername(username);
        //SecurityUser securityUser = new SecurityUser();
        return null;
    }
}
