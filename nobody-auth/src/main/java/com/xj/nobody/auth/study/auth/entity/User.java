package com.xj.nobody.auth.study.auth.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class User implements UserDetails {

    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    /**
     * id
     */
    private Integer id;

    /**
     * username
     */
    private String username;

    /**
     * password
     */
    private String password;

    /**
     * enabled
     */
    private int enabled;

    /**
     * accountnonexpired
     */
    private int accountnonexpired;

    /**
     * accountnonlocked
     */
    private int accountnonlocked;

    /**
     * credentialsnonexpired
     */
    private int credentialsnonexpired;
    @TableField(exist = false)
    private List<Role> roles = new ArrayList<>();
    public User() {}

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        for (Role role : roles) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
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
        return this.accountnonexpired == 1;
    }

    @Override
    public boolean isAccountNonLocked() {
        return this.accountnonlocked == 1;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return this.credentialsnonexpired == 1;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled == 1;
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

    public void setPassword(String password) {
        this.password = password;
    }

    public int getEnabled() {
        return enabled;
    }

    public void setEnabled(int enabled) {
        this.enabled = enabled;
    }

    public int getAccountnonexpired() {
        return accountnonexpired;
    }

    public void setAccountnonexpired(int accountnonexpired) {
        this.accountnonexpired = accountnonexpired;
    }

    public int getAccountnonlocked() {
        return accountnonlocked;
    }

    public void setAccountnonlocked(int accountnonlocked) {
        this.accountnonlocked = accountnonlocked;
    }

    public int getCredentialsnonexpired() {
        return credentialsnonexpired;
    }

    public void setCredentialsnonexpired(int credentialsnonexpired) {
        this.credentialsnonexpired = credentialsnonexpired;
    }
}
