package com.supportportal.resource;

import com.supportportal.exception.domain.ExceptionHandling;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/user")
public class UserResource extends ExceptionHandling {


    @GetMapping("/getUser")
    public String showUser(){
        return "Hello World";
    }
}
