package com.xj.nobody.admin.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.xj.nobody.commons.domain.BaseEntity;
import com.xj.nobody.commons.validate.ValidateGroup;
import lombok.Data;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Data
@TableName(value = "sys_menu")
public class SysMenu extends BaseEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    @NotNull(message = "数据不存在",groups = {ValidateGroup.UpdateGroup.class})
    private Integer id;

    /**
     * 父级ID
     */
    @TableField(value = "parent_id")
    @NotNull(message = "请选择父菜单",groups = {ValidateGroup.AddGroup.class})
    private Integer parentId;

    /**
     * 菜单名称
     */
    @TableField(value = "title")
    @NotEmpty(message = "请输入菜单名称",groups = {ValidateGroup.AddGroup.class})
    private String title;

    /**
     * 菜单级数
     */
    @TableField(value = "level")
    private Integer level;

    /**
     * 菜单地址
     */
    @TableField(value = "path")
    @NotEmpty(message = "请输入菜单地址",groups = {ValidateGroup.AddGroup.class})
    private String path;
    /**
     * route name
     */
    @TableField(value = "name")
    @NotEmpty(message = "请输入路由名称",groups = {ValidateGroup.AddGroup.class})
    private String name;
    /**
     * 菜单排序
     */
    @TableField(value = "sort")
    @NotNull(message = "请输入菜单排序",groups = {ValidateGroup.AddGroup.class})
    private Integer sort;

    /**
     * 是否隐藏[0]否[1]是
     */
    @TableField(value = "hidden")
    private Integer hidden;

    /**
     * 前端图标
     */
    @TableField(value = "icon")
    private String icon;

    @TableField(exist = false)
    private List<SysMenu> children;

    public void addChildren(SysMenu menu) {
        if (children == null) {
            children = new ArrayList<>();
        }
        children.add(menu);
    }
}
