package com.all4tic.jwtapp.services;

import com.all4tic.jwtapp.entities.User;
import com.all4tic.jwtapp.exception.EmailExistException;
import com.all4tic.jwtapp.exception.EmailNotFoundException;
import com.all4tic.jwtapp.exception.UserNotFoundException;
import com.all4tic.jwtapp.exception.UsernameExistException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import java.io.IOException;
import java.util.List;

public interface UserService {
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException;
    User register(String firstName, String lastName , String username, String email) throws UserNotFoundException, EmailExistException, UsernameExistException, MessagingException;
    List<User> getUsers();
    User findUserByUsername(String username);
    User findUserByEmail(String  email) ;
    User addNewUser(String firstName, String lastName , String username, String email, String role, boolean isNonLocked, boolean isActive,
                    MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
    User updateUser(String curreUsername, String firstName, String lastName , String username, String email, String role, boolean isNonLocked, boolean isActive,
                    MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;
    void deleteUser(long id);
    void resetPassword(String email) throws MessagingException, EmailNotFoundException;
    User updateProfileImage(String username, MultipartFile profileImage) throws UserNotFoundException, EmailExistException, UsernameExistException, IOException;

}
