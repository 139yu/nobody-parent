package com.xj.nobody.admin.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.xj.nobody.commons.domain.BaseEntity;
import lombok.Data;

import java.io.Serializable;

@Data
@TableName(value = "sys_role",excludeProperty = {"sort"})
public class SysRole extends BaseEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    /**
     * id
     */
    private Integer id;

    /**
     * 名称
     */
    private String name;

    /**
     * 描述
     */
    private String description;

    /**
     * 排序
     */
    private Integer sort;

    /**
     * 启用状态[0]禁用 [1]启用
     */
    private Integer status;


}
