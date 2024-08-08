package com.xj.nobody.commons.constants;

public interface AuthConstants {

    String JWT_TOKEN_HEADER = "Authorization";
    String AUTH_TOKEN_PREFIX = "Bearer ";

    String AUTHORITY_PREFIX = "ROLE_";
    String AUTHORITY_CLAIM_NAME = "authorities";
    /**
     * 认证异常信息
     */
    String ACCOUNT_DISABLE = "账号已被禁用";

    String ACCOUNT_NOT_EXIST = "账号不存在";

    String ACCOUNT_PASSWORD_ERROR = "用户名或密码错误";

    String ACCOUNT_LOCKED = "账号已被锁定";

    String ACCOUNT_EXPIRED = "账号已过期";

    String ACCOUNT_CREDENTIAL_EXPIRED = "登录凭证已过期";

    String ADMIN_CLIENT_ID = "nobody-admin";
    String DEFAULT_GRANT_TYPE = "password";
    String CLIENT_SECRET = "nobody";
    String SUPER_ROLE = "nobody";
}
