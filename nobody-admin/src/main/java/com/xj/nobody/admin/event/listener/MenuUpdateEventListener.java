package com.xj.nobody.admin.event.listener;

import com.xj.nobody.admin.enums.MenuEventType;
import com.xj.nobody.admin.event.MenuUpdateEvent;
import com.xj.nobody.admin.mapper.SysRoleMapper;
import com.xj.nobody.admin.service.SysRoleMenuService;
import com.xj.nobody.admin.service.SysRoleService;
import com.xj.nobody.commons.constants.AuthConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;


/**
 * 为超级管理员角色添加菜单
 */
@Component
public class MenuUpdateEventListener {
    @Autowired
    private SysRoleService roleService;
    @Autowired
    private SysRoleMenuService roleMenuService;
    @EventListener(MenuUpdateEvent.class)
    public void onApplicationEvent(MenuUpdateEvent event) {
        MenuEventType eventType = event.getEventType();
        Integer menuId = event.getMenuId();
        if (MenuEventType.ADD == eventType) {
            roleService.checkAndAddMenu(AuthConstants.SUPER_ROLE,menuId);
        }
        else if(MenuEventType.DELETE == eventType){
            //roleService.checkAndDeleteMenu(AuthConstants.SUPER_ROLE,menuId);
            roleMenuService.deleteRelation(menuId);
        }
    }
}
