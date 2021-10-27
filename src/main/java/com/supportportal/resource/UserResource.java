package com.supportportal.resource;

import com.supportportal.domain.HttpResponse;
import com.supportportal.domain.User;
import com.supportportal.domain.UserPrincipal;
import com.supportportal.exception.domain.*;
import com.supportportal.payload.AddNewUserRequest;
import com.supportportal.payload.LoginRequest;
import com.supportportal.payload.RegistrationRequest;
import com.supportportal.payload.UpdateUserForm;
import com.supportportal.service.UserService;
import com.supportportal.utility.JWTTokenProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;

import static com.supportportal.constant.FileConstant.*;
import static com.supportportal.constant.SecurityConstant.JWT_TOKEN_HEADER;
import static org.springframework.http.HttpStatus.*;
import static org.springframework.http.MediaType.IMAGE_JPEG_VALUE;

@RestController
@RequestMapping(path = {"/", "/user"})
public class UserResource extends ExceptionHandling {

    public static final String PASSWORD_RESET_EMAIL = "Email with new password was sent to ";
    public static final String USER_DELETED_SUCCESSFULLY = "User deleted successfully";
    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JWTTokenProvider jwtTokenProvider;


    @PostMapping(path = {"/","/register"})
    public ResponseEntity<?> register(@RequestBody RegistrationRequest request) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException {
        User user = userService.register(request);
        return new ResponseEntity<>(user, CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest request) throws UserNotFoundException, EmailExistException, UsernameExistException {
        authenticate(request.getUsername(), request.getPassword());
        User loginUser = userService.findUserByUsername(request.getUsername());
        UserPrincipal userPrincipal = new UserPrincipal(loginUser);
        HttpHeaders jwtHeader = getJwtHeader(userPrincipal);
        return new ResponseEntity<>(loginUser, jwtHeader, OK);
    }

    @PostMapping("/add")
    public ResponseEntity<?> addNewUser(@RequestBody AddNewUserRequest request) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {
        return new ResponseEntity<>(userService.addNewUser(request), CREATED);
    }

    @PostMapping("/update")
    public ResponseEntity<?> updateUser(@RequestBody UpdateUserForm request) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {
        return new ResponseEntity<>(userService.updateUser(request), ACCEPTED);
    }

    @GetMapping("/all")
    public ResponseEntity<?> getAllUser(){
        return new ResponseEntity<>(userService.getUsers(), FOUND);
    }

    @GetMapping("/find/{username}")
    public ResponseEntity<?> getUserByUsername(@PathVariable String username){
        return new ResponseEntity<>(userService.findUserByUsername(username), FOUND);
    }

    @PutMapping("/resetPassword/{email}")
    public ResponseEntity<?> resetPassword(@PathVariable String email) throws EmailNotFoundException, MessagingException {
        userService.resetPassword(email);
        return response(OK, PASSWORD_RESET_EMAIL + email);
    }

    @DeleteMapping("/delete/{id}")
    @PreAuthorize("hasAnyAuthority('user:delete')")
    public ResponseEntity<?> deleteUser(@PathVariable Long id){
        userService.deleteUser(id);
        return response(NO_CONTENT, USER_DELETED_SUCCESSFULLY);
    }

    @PostMapping("/updateProfileImage")
    public ResponseEntity<?> updateProfileImage(@RequestParam("username") String username,
                                                @RequestParam(value = "profileImage")MultipartFile profileImage) throws UserNotFoundException, EmailExistException, IOException, UsernameExistException {
        return new ResponseEntity<>(userService.updateProfileImage(username, profileImage), OK);
    }

    @GetMapping(path = "/image/{username}/{fileName}", produces = IMAGE_JPEG_VALUE)
    public byte[] getProfileImage(@PathVariable("username") String username, @PathVariable("fileName") String fileName) throws IOException {
        return Files.readAllBytes(Paths.get(USER_FOLDER + username + FORWARD_SLASH + fileName));
    }

    @GetMapping(path = "/image/profile/{username}", produces = IMAGE_JPEG_VALUE)
    public byte[] getTempProfileImage(@PathVariable("username") String username) throws IOException {
        URL url = new URL(TEMP_PROFILE_IMAGE_BASE_URL + username);
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try(InputStream inputStream = url.openStream()){
            int byteRead;
            byte[] chunk = new byte[1024];
            while ((byteRead = inputStream.read(chunk)) > 0){
                byteArrayOutputStream.write(chunk, 0, byteRead);
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HttpResponse(httpStatus.value(),
                httpStatus, httpStatus.getReasonPhrase().toUpperCase(),
                message.toUpperCase()), httpStatus);
    }

    private HttpHeaders getJwtHeader(UserPrincipal userPrincipal) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtToken(userPrincipal));
        return headers;
    }

    private void authenticate(String username, String password) throws UserNotFoundException, UsernameExistException, EmailExistException{
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(username, password));
    }
}
