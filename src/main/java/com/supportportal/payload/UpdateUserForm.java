package com.supportportal.payload;

import lombok.Data;
import org.springframework.web.multipart.MultipartFile;

@Data
public class UpdateUserForm {
    private String currentUsername;
    private String newFirstName;
    private String newLastName;
    private String newUsername;
    private String newEmail;
    private String role;
    private String newRole;
    private boolean isNonLocked;
    private boolean isActive;
    private MultipartFile profileImage;
}
