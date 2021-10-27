package com.supportportal.service;

import com.supportportal.domain.User;
import com.supportportal.exception.domain.EmailExistException;
import com.supportportal.exception.domain.UserNotFoundException;
import com.supportportal.exception.domain.UsernameExistException;
import com.supportportal.payload.LoginRequest;
import com.supportportal.payload.RegistrationRequest;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import java.util.List;

@Service
public interface UserService {
    User register(RegistrationRequest request) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException;
    List<User> getUsers();
    User findUserByUsername(String username);
    User findUserByEmail(String email);

    User login(LoginRequest request) throws UserNotFoundException, UsernameExistException, EmailExistException;
}
