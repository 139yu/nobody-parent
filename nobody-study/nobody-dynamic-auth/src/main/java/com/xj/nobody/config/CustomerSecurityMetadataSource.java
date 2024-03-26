package com.xj.nobody.config;

import com.xj.nobody.entity.Menu;
import com.xj.nobody.entity.Role;
import com.xj.nobody.mapper.MenuMapper;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

import javax.annotation.Resource;
import java.util.Collection;
import java.util.List;

@Component
public class CustomerSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

    @Resource
    private MenuMapper menuMapper;
    AntPathMatcher antPathMatcher = new AntPathMatcher();

    /**
     * 返回当前请求所需要的角色
     * @param o 受保护对象
     * @return
     * @throws IllegalArgumentException
     */
    @Override
    public Collection<ConfigAttribute> getAttributes(Object o) throws IllegalArgumentException {
        String requestURI = ((FilterInvocation) o).getRequest().getRequestURI();
        List<Menu> allMenu = menuMapper.getAllMenu();
        for (Menu menu : allMenu) {
            if (antPathMatcher.match(menu.getPattern(),requestURI)){
                List<Role> roles = menu.getRoles();
                String[] roleNames = roles.stream().map(r -> r.getName()).toArray(String[]::new);
                return SecurityConfig.createList(roleNames);
            }
        }
        return null;
    }

    @Override
    public Collection<ConfigAttribute> getAllConfigAttributes() {
        return null;
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return FilterInvocation.class.isAssignableFrom(aClass);
    }
}
