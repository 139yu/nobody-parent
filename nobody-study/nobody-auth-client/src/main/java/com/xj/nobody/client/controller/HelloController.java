package com.xj.nobody.client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

@Controller
public class HelloController {
    @Autowired
    private WebClient webClient;

    private String helloUri = "http://res.nobody.com:9003/hello";

    @GetMapping(value = "/authorize",params = "grant_type=authorization_code")
    public String authorizationCodeGrant(Model model){
        String msg = retrieveMessages("auth-code");
        model.addAttribute("msg",msg);
        return "index";
    }
    @GetMapping(value = "/authorize",params = "grant_type=client_credentials")
    public String authorizationCredentialsGrant(Model model){
        String msg = retrieveMessages("client-creds");
        model.addAttribute("msg",msg);
        return "index";
    }
    @GetMapping(value = "/authorize",params = "grant_type=password")
    public String authorizationPasswordGrant(Model model){
        String msg = retrieveMessages("password");
        model.addAttribute("msg",msg);
        return "index";
    }

    private String retrieveMessages(String clientRegistrationId){
        return webClient
                .get()
                .uri(helloUri)
                .attributes(clientRegistrationId(clientRegistrationId))
                .retrieve()
                .bodyToMono(String.class)
                .block();
    }

    @GetMapping("/")
    public String root(){
        return "redirect:index";
    }

    @GetMapping("index")
    public String index(){
        return "index";
    }
}
