package com.xj.nobody.admin.component;

import com.xj.nobody.admin.service.SysRoleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;

@Component
public class ResourceLoadHolder {

    @Autowired
    private SysRoleService roleService;

    @PostConstruct
    public void init(){
        roleService.loadRoleResourceCache();
    }
}
