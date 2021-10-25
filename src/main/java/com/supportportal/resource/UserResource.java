package com.supportportal.resource;

import com.supportportal.domain.User;
import com.supportportal.exception.domain.EmailExistException;
import com.supportportal.exception.domain.ExceptionHandling;
import com.supportportal.exception.domain.UserNotFoundException;
import com.supportportal.exception.domain.UsernameExistException;
import com.supportportal.payload.RegistrationRequest;
import com.supportportal.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.HttpStatus.CREATED;

@RestController
@RequestMapping(path = {"/", "/user"})
public class UserResource extends ExceptionHandling {

    @Autowired
    private UserService userService;


    @PostMapping(path = {"/","/register"})
    public ResponseEntity<?> showUser(@RequestBody RegistrationRequest request) throws UserNotFoundException, EmailExistException, UsernameExistException {
        User user = userService.register(request);
        return new ResponseEntity<>(user, CREATED);
    }
}
