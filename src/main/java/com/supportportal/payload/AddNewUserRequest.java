package com.supportportal.payload;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class AddNewUserRequest {
    private String firstName;
    private String lastName;
    private String username;
    private String email;
    private String role;
    private boolean isNonLocked;
    private boolean isActive;
    private MultipartFile profileImage;
}
