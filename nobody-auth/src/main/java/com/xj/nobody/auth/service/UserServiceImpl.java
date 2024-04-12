package com.xj.nobody.auth.service;

import com.xj.nobody.auth.domain.SecurityUser;
import com.xj.nobody.auth.feign.AdminFeignClient;
import com.xj.nobody.commons.constants.AuthConstants;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
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
        if (userDTO == null) {
            throw new UsernameNotFoundException(AuthConstants.ACCOUNT_PASSWORD_ERROR);
        }
        SecurityUser user = new SecurityUser(userDTO);
        if (!user.isEnabled()) {
            throw new DisabledException(AuthConstants.ACCOUNT_DISABLE);
        } else if (!user.isAccountNonLocked()) {
            throw new LockedException(AuthConstants.ACCOUNT_LOCKED);
        }else if(!user.isAccountNonExpired()){
            throw new AccountExpiredException(AuthConstants.ACCOUNT_EXPIRED);
        }else if(user.isCredentialsNonExpired()){
            throw new AccountExpiredException(AuthConstants.ACCOUNT_CREDENTIAL_EXPIRED);
        }
        return user;
    }
}
