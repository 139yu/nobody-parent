package com.xj.nobody.commons.domain;

/**
 * 返回实例
 */
public class R<T> {
    /**
     *成功0，警告301 错误500
     */
    private int code;
    /**
     * 返回信息
     */
    private String msg;
    /**
     * 返回数据
     */
    private T data;

    public R() {

    }

    public R(int code, String msg, T data) {
        this.code = code;
        this.msg = msg;
        this.data = data;
    }

    /**
     * 状态类型
     */
    public enum Type {
        /**
         * 成功
         */
        SUCCESS(0,"success"),
        /**
         * 警告
         */
        WARN(301,"warn"),
        /**
         * 错误
         */
        ERROR(500,"error");
        private final int value;
        private final String msg;
        Type(int value,String msg) {
            this.value = value;
            this.msg = msg;
        }

        public int value() {
            return this.value;
        }

        public String msg() {
            return msg;
        }
    }


    public static R success(String msg,Object data){
        return new R(Type.SUCCESS.value(), msg,data);
    }

    public static R success(Object data){
        return success(Type.SUCCESS.msg(),data);
    }

    public static R success(){
        return success(null);
    }

    public static R error(){
        return new R(Type.ERROR.value(), Type.ERROR.msg(), null);
    }

    public static R error(String msg){
        return new R(Type.ERROR.value(), msg, null);
    }

    public static R warn(){
        return new R(Type.WARN.value(), Type.WARN.msg(), null);
    }

    public static R warn(String msg){
        return new R(Type.WARN.value(), msg, null);
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public T getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }
}
