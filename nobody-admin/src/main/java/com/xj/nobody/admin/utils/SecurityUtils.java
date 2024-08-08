package com.xj.nobody.admin.utils;

import cn.hutool.json.JSON;
import cn.hutool.json.JSONUtil;
import com.nimbusds.jose.JWSObject;
import com.xj.nobody.commons.constants.AuthConstants;
import com.xj.nobody.commons.dto.UserDTO;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.text.ParseException;

public class SecurityUtils {
    /**
     * 获取当前登录用户
     * @return
     * @throws ParseException
     */
    public static UserDTO getCurrentUser() throws ParseException {
        HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
        String token = request.getHeader(AuthConstants.JWT_TOKEN_HEADER);
        if (token == null) {
            return null;
        }
        String realToken = token.replace(AuthConstants.AUTH_TOKEN_PREFIX, "");
        JWSObject jwsObject = JWSObject.parse(realToken);
        String userStr = jwsObject.getPayload().toString();
        return JSONUtil.toBean(userStr,UserDTO.class);
    }
}
