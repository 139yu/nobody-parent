package com.xj.nobody.admin.domain;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableField;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import com.xj.nobody.commons.domain.BaseEntity;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;
import java.util.List;

@Data
@TableName(value = "sys_user",excludeProperty = {"sort"})
public class SysUser extends BaseEntity implements Serializable {
    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    private Integer id;

    /**
     * 用户名
     */
    private String username;

    /**
     * 密码
     */
    private String password;
    /**
     * 昵称
     */
    private String nickname;

    /**
     * 最后登录时间
     */
    private Date loginTime;


    /**
     * 邮箱
     */
    private String email;

    private Integer enable;

    @TableField(exist = false)
    private List<SysRole> roleList;
}
