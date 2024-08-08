package com.xj.nobody.admin.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.xj.nobody.admin.domain.SysMenu;
import com.xj.nobody.admin.enums.MenuEventType;
import com.xj.nobody.admin.event.MenuUpdateEvent;
import com.xj.nobody.admin.mapper.SysMenuMapper;
import com.xj.nobody.admin.service.SysMenuService;
import com.xj.nobody.commons.exception.BusinessException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Service
public class SysMenuServiceImpl implements SysMenuService {
    @Autowired
    private SysMenuMapper menuMapper;
    @Autowired
    private ApplicationEventPublisher eventPublisher;

    @Override
    public List<SysMenu> getUserMenus(Integer userId) {
        List<SysMenu> userMenus = menuMapper.getUserMenu(userId);
        return parseToTree(userMenus);
    }

    @Cacheable(value = "menuTree")
    @Override
    public List<SysMenu> listTree() {
        List<SysMenu> menus = menuMapper.selectList(Wrappers.lambdaQuery(SysMenu.class).orderByAsc(SysMenu::getSort));
        return parseToTree(menus);
    }

    @CacheEvict(value = "menuTree", allEntries = true)
    @Override
    public int addMenu(SysMenu menu) throws BusinessException {
        Integer parentId = menu.getParentId();
        if (parentId == 0) {
            menu.setLevel(1);
        }else {
            SysMenu parent = menuMapper.selectById(parentId);
            if (parent == null && parentId != 0) {
                throw new BusinessException("父菜单不存在！");
            }
            menu.setLevel(parent.getLevel() + 1);
        }

        if (exists(menu)) {
            throw new BusinessException("菜单名称或路由名称或路由重复！");
        }
        int insert = menuMapper.insert(menu);
        eventPublisher.publishEvent(new MenuUpdateEvent(this, MenuEventType.ADD, menu.getId()));
        return insert;
    }

    @Override
    public boolean exists(SysMenu menu) {
        return menuMapper.selectExists(menu) > 0;
    }

    @CacheEvict(value = "menuTree", allEntries = true)
    @Override
    public int updateMenu(SysMenu menu) throws BusinessException {
        SysMenu dbMenu = menuMapper.selectById(menu.getId());
        Integer parentId = menu.getParentId();
        if (parentId != null) {
            if (parentId.equals(menu.getId())) {
                throw new BusinessException("不可选择当前菜单为父级菜单！");
            }
            if (parentId != 0) {
                SysMenu parent = menuMapper.selectById(parentId);
                 if (parent == null) {
                    throw new BusinessException("父菜单不存在！");
                }
                if (Objects.equals(dbMenu.getParentId(), parent.getParentId())){
                    throw new BusinessException("不可相互引用");
                }
                menu.setLevel(parent.getLevel() + 1);
            }
            else {
                menu.setLevel(1);
            }
        }
        if ((menu.getName() != null || menu.getPath() != null || menu.getTitle() != null) && !unique(menu)) {
            throw new BusinessException("菜单名称或路由名称或路由重复！");
        }
        return menuMapper.updateById(menu);
    }

    @Override
    public boolean unique(SysMenu menu) {
        return !(menuMapper.unique(menu) > 0);
    }

    @CacheEvict(value = "menuTree", allEntries = true)
    @Override
    public int delete(Integer id) throws BusinessException {
        Long count = menuMapper.selectCount(Wrappers.lambdaQuery(SysMenu.class).eq(SysMenu::getParentId, id));
        if (count > 0) {
            throw new BusinessException("有子菜单，无法删除");
        }
        eventPublisher.publishEvent(new MenuUpdateEvent(this, MenuEventType.DELETE, id));
        return menuMapper.deleteById(id);
    }

    /**
     * 构建菜单树
     * @param menus
     * @return
     */
    private List<SysMenu> parseToTree(List<SysMenu> menus){
        return menus
                .stream()
                .filter(item -> item.getLevel() == 1)
                .map(item -> buildNode(item,menus))
                .collect(Collectors.toList());
    }

    private SysMenu buildNode(SysMenu parent,List<SysMenu> menus){
        List<SysMenu> children = menus
                .stream()
                .filter(item -> item.getParentId() != null && item.getParentId().equals(parent.getId()))
                .map(item -> buildNode(item, menus))
                .collect(Collectors.toList());
        parent.setChildren(children);
        return parent;
    }
}
