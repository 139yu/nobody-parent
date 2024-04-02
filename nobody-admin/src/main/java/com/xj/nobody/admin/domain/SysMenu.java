package com.xj.nobody.admin.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.xj.nobody.commons.domain.BaseEntity;
import lombok.Data;

import java.io.Serializable;

@Data
@TableName(value = "sys_role")
public class SysMenu extends BaseEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    private Integer id;

    /**
     * 父级ID
     */
    private Long parentId;

    /**
     * 菜单名称
     */
    private String title;

    /**
     * 菜单级数
     */
    private Integer level;

    /**
     * 菜单地址
     */
    private String path;

    /**
     * 菜单类型[0]目录[1]菜单[2]按钮
     */
    private Integer menuType;

    /**
     * 菜单排序
     */
    private Integer sort;

    /**
     * 显示状态[0]隐藏[1]显示
     */
    private Integer showStatus;

    /**
     * 前端图标
     */
    private String icon;


    /**
     * 权限字符串
     */
    private String perms;
}
