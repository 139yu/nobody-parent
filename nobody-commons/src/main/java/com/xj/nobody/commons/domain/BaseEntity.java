package com.xj.nobody.commons.domain;

import com.baomidou.mybatisplus.annotation.TableField;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class BaseEntity {
    private Date createTime;
    @TableField(exist = false)
    private Map<String,Object> params;
    @TableField(exist = false)
    private String orderBy;
    @TableField(exist = false)
    private String sorted;

    public Date getCreateTime() {
        return createTime;
    }

    public void setCreateTime(Date createTime) {
        this.createTime = createTime;
    }

    public Map<String, Object> getParams() {
        if (params == null) {
            params = new HashMap<>();
        }
        return params;
    }

    public void setParams(Map<String, Object> params) {
        this.params = params;
    }

    public void putParam(String key,Object value){
        getParams().put(key,value);
    }

    public String getOrderBy() {
        return orderBy;
    }

    public void setOrderBy(String orderBy) {
        this.orderBy = orderBy;
    }

    public String getSorted() {
        return sorted;
    }

    public void setSorted(String sorted) {
        this.sorted = sorted;
    }
}
