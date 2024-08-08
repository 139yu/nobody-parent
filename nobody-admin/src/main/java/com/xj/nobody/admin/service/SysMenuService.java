package com.xj.nobody.admin.service;

import com.xj.nobody.admin.domain.SysMenu;
import com.xj.nobody.commons.exception.BusinessException;

import java.util.List;

public interface SysMenuService {
    /**
     * 查询用户菜单并组装成菜单树
     * @param userId
     * @return
     */
    List<SysMenu> getUserMenus(Integer userId);

    List<SysMenu> listTree();

    int addMenu(SysMenu menu) throws BusinessException;

    boolean exists(SysMenu menu);

    int updateMenu(SysMenu menu) throws BusinessException;

    /**
     * 关键校验是否唯一
     * @param menu
     * @return
     */
    boolean unique(SysMenu menu);

    int delete(Integer id) throws BusinessException;
}
