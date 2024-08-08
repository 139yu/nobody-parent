package com.xj.nobody.amdin.mapper;

import com.xj.nobody.admin.NobodyAdminApplication;
import com.xj.nobody.admin.domain.SysMenu;
import com.xj.nobody.admin.mapper.SysMenuMapper;
import lombok.val;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import javax.annotation.Resource;

@SpringBootTest(classes = NobodyAdminApplication.class)
public class MenuMapperTest {
    @Resource
    private SysMenuMapper menuMapper;

    @Test
    public void generateMenu(){
        SysMenu perms = new SysMenu();
        perms.setParentId(0);
        perms.setTitle("权限管理");
        perms.setLevel(1);
        perms.setPath("/perms");
        perms.setSort(100);
        perms.setHidden(0);
        perms.setIcon("Lock");
        int insert = menuMapper.insert(perms);
        if (perms.getId() != null) {
            SysMenu role = new SysMenu();
            role.setParentId(perms.getId());
            role.setTitle("角色列表");
            role.setLevel(2);
            role.setPath("/perms/role");
            role.setSort(2);
            role.setIcon("UserFilled");
            menuMapper.insert(role);
            SysMenu user = new SysMenu();
            user.setParentId(perms.getId());
            user.setTitle("用户列表");
            user.setLevel(2);
            user.setPath("/perms/user");
            user.setSort(1);
            user.setIcon("User");
            menuMapper.insert(user);
            SysMenu resource = new SysMenu();
            resource.setParentId(perms.getId());
            resource.setTitle("资源列表");
            resource.setLevel(2);
            resource.setPath("/perms/resource");
            resource.setSort(3);
            resource.setIcon("Star");
            menuMapper.insert(resource);
        }
        SysMenu system = new SysMenu();
        system.setParentId(0);
        system.setTitle("系统管理");
        system.setLevel(1);
        system.setPath("/system");
        system.setSort(101);
        system.setHidden(0);
        system.setIcon("Setting");
        menuMapper.insert(system);
        if (system.getId() != null) {
            val menu = new SysMenu();
            menu.setParentId(system.getParentId());
            menu.setTitle("菜单列表");
            menu.setLevel(1);
            menu.setPath("/system/menu");
            menu.setSort(100);
            menu.setHidden(0);
            menu.setIcon("Monitor");
            menuMapper.insert(menu);
        }
    }


}
