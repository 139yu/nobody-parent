package com.xj.nobody.auth.study.authdemo;

import lombok.Getter;
import lombok.Setter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
public class Role implements GrantedAuthority {
    private String name;
    private List<SimpleGrantedAuthority> allowedOperations = new ArrayList<>();

    @Override
    public String getAuthority() {
        return this.name;
    }
}
