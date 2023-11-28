package com.xj.nobody.auth;

import com.xj.nobody.NobodyAuthApplication;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.StringUtils;

import java.util.Base64;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(classes = NobodyAuthApplication.class)
public class PasswordTest {


    @Test
    public void encode(){
        Pbkdf2PasswordEncoder encoder = new Pbkdf2PasswordEncoder();
        System.out.println(encoder.encode("123"));
    }


    @Test
    public void base64(){
        String cookieValue = "TlZwd2R4T1FqZXg2QU1WJTJCc2ZvZ1dnJTNEJTNEOmlmT2hubGZ2cGM0N0JKN0VkSjRmRFElM0QlM0Q";
        for (int j = 0; j < cookieValue.length() % 4; j++) {
            cookieValue = cookieValue + "=";
        }
        String cookieAsPlainText = new String(Base64.getDecoder().decode(cookieValue.getBytes()));

        String[] tokens = StringUtils.delimitedListToStringArray(cookieAsPlainText,
                ":");
        for (String token : tokens) {
            System.out.println(token);
        }
    }
}
