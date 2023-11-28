package com.xj.nobody.system.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;

import java.util.Date;

@Data
public class SysMenu {
    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    private Integer id;
    /**
     * menu_name
     */
    private String menuName;

    /**
     * 权限标识
     */
    private String perms;

    /**
     * menu_url
     */
    private String menuUrl;

    /**
     * 菜单图标
     */
    private String icon;

    /**
     * 父菜单
     */
    private Integer parentId;

    /**
     * 排序
     */
    private int sort;

    /**
     * 0隐藏1显示
     */
    private int status;

    /**
     * 0目录1菜单0按钮
     */
    private int menuType;

    /**
     * create_time
     */
    private Date createTime;
}
