package com.xj.nobody.admin.service;


import com.xj.nobody.admin.domain.SysRole;

import java.util.List;

public interface SysRoleService {

    List<SysRole> list(SysRole params);

    List<SysRole> listByUserId(Integer userId);

    void loadRoleResourceCache();

    /**
     * 检查角色是否拥有菜单，如果没有则添加
     * @param roleKey
     * @param menuId
     */
    void checkAndAddMenu(String roleKey, Integer menuId);

    /**
     * 检查角色是否拥有菜单，如果有则删除
     * @param roleKey
     * @param menuId
     */
    void checkAndDeleteMenu(String roleKey, Integer menuId);
}
