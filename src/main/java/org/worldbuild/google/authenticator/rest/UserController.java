package org.worldbuild.google.authenticator.rest;

import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.worldbuild.google.authenticator.entity.User;
import org.worldbuild.google.authenticator.enums.AuthenticationStatus;
import org.worldbuild.google.authenticator.service.TotpService;
import org.worldbuild.google.authenticator.service.UserDetailsServiceImpl;
import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;

@Log4j2
@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    @Qualifier("passwordEncoder")
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsServiceImpl userDetailsServiceImpl;

    @RequestMapping(value = "/register/{username}/{password}", method = RequestMethod.POST)
    public String register(@PathVariable String username, @PathVariable String password) {
        User user = userDetailsServiceImpl.register(username, password);
        String encodedSecret = new Base32().encodeToString(user.getSecretKey().getBytes());
        // This Base32 encode may usually return a string with padding characters - '='.
        // QR generator which is user (zxing) does not recognize strings containing symbols other than alphanumeric
        // So just remove these redundant '=' padding symbols from resulting string
        return encodedSecret.replace("=", "");
    }

    @RequestMapping(value = "/login/{username}/{password}",method =  RequestMethod.POST)
    public AuthenticationStatus login(@PathVariable String username, @PathVariable String password) {
        User user = (User) userDetailsServiceImpl.loadUserByUsername(username);
        if (passwordEncoder.matches(password,user.getPassword())) {
            return AuthenticationStatus.REQUIRE_TOKEN_CHECK;
        }
        SecurityContextHolder.clearContext();
        return AuthenticationStatus.FAILED;
    }

    @Autowired
    private TotpService totpService;

    @RequestMapping(value = "/authenticate/token/{username}/{token}",method =  RequestMethod.POST)
    public AuthenticationStatus tokenCheck(@PathVariable(value = "username",required = true)  String username, @PathVariable(value = "token",required = true) String token) {
        User user = (User) userDetailsServiceImpl.loadUserByUsername(username);
        if (totpService.verifyCode(token, user.getSecretKey())) {
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, user.getPassword(),new ArrayList<>());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return AuthenticationStatus.AUTHENTICATED;
        }
        SecurityContextHolder.clearContext();
        return AuthenticationStatus.FAILED;
    }

    @RequestMapping(value = "/logout", method = RequestMethod.POST)
    public AuthenticationStatus logout() {
        SecurityContextHolder.clearContext();
        return AuthenticationStatus.LOG_OUT;
    }
}
