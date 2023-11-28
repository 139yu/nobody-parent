package com.xj.nobody.commons.entitys;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import lombok.Data;

import java.io.Serializable;
import java.util.Date;


@Data
public class SysUser implements Serializable {

    private static final long serialVersionUID = 1L;

    @TableId(type = IdType.AUTO)
    private Integer id;
    /**
     * login_name
     */
    private String loginName;

    /**
     * passwd
     */
    private String passwd;

    /**
     * 加密盐
     */
    private String salt;

    /**
     * email
     */
    private String email;

    /**
     * phone
     */
    private String phone;

    /**
     * [0]禁用[1]启用
     */
    private int status;

    /**
     * create_time
     */
    private Date createTime;

    private Date lastTime;
    public SysUser() {}
}
