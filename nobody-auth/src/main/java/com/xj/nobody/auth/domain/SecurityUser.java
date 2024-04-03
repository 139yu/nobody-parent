package com.xj.nobody.auth.domain;

import com.xj.nobody.commons.dto.MenuDTO;
import com.xj.nobody.commons.dto.RoleDTO;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;


public class SecurityUser implements UserDetails {
    private Integer id;
    private String username;
    private Boolean enabled;
    private String password;
    private Collection<SimpleGrantedAuthority> authorities;

    public SecurityUser(UserDTO userDTO) {
        List<RoleDTO> roleList = userDTO.getRoleList();
        authorities = new ArrayList<>();
        for (RoleDTO roleDTO : roleList) {
            List<MenuDTO> menuList = roleDTO.getMenuList();
            for (MenuDTO menuDTO : menuList) {
                authorities.add(new SimpleGrantedAuthority(menuDTO.getPerms()));
            }
        }
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setAuthorities(Collection<SimpleGrantedAuthority> authorities) {
        this.authorities = authorities;
    }
}
