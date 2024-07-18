package com.xj.nobody.auth;

import com.xj.nobody.NobodyAuthApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootTest(classes = NobodyAuthApplication.class)
public class PasswordEncoderTest {
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    public void test(){
        String nobody = passwordEncoder.encode("nobody");
        System.out.println(nobody);
    }
}
