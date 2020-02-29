package org.worldbuild.google.authenticator.service;

import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.worldbuild.google.authenticator.entity.User;
import org.worldbuild.google.authenticator.utils.TOTPUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Log4j2
@Service("userDetailsServiceImpl")
public class UserDetailsServiceImpl implements UserDetailsService {

    private static final List<User> users = new ArrayList<>();

    @Autowired
    @Qualifier("passwordEncoder")
    private PasswordEncoder passwordEncoder;

    public User register(String username, String password) {
        User user = new User(username, passwordEncoder.encode(password), TOTPUtils.generateSecret(10));
        users.add(user);
        return user;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
         Optional<User> user=users.stream()
                .filter(ur -> ur.getUsername().equals(username))
                .findFirst();
         if (user.isPresent()){
             log.info(user.get());
             return  user.get();
         }
         throw  new UsernameNotFoundException("User does not exist "+username);
    }
}
