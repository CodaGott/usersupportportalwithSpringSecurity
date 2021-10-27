package com.supportportal.service;

import com.supportportal.domain.User;
import com.supportportal.exception.domain.EmailExistException;
import com.supportportal.exception.domain.EmailNotFoundException;
import com.supportportal.exception.domain.UserNotFoundException;
import com.supportportal.exception.domain.UsernameExistException;
import com.supportportal.payload.AddNewUserRequest;
import com.supportportal.payload.LoginRequest;
import com.supportportal.payload.RegistrationRequest;
import com.supportportal.payload.UpdateUserForm;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

@Service
public interface UserService {
    User register(RegistrationRequest request) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException;
    List<User> getUsers();
    User findUserByUsername(String username);
    User findUserByEmail(String email);

    User login(LoginRequest request) throws UserNotFoundException, UsernameExistException, EmailExistException;

    User addNewUser(AddNewUserRequest request) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    User updateUser (UpdateUserForm form) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

    void deleteUser(Long id);

    void resetPassword(String email) throws MessagingException, EmailNotFoundException;

    User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
}
