package org.worldbuild.google.authenticator.rest;

import lombok.extern.log4j.Log4j2;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;
import org.worldbuild.google.authenticator.entity.User;

@Log4j2
@RestController
public class DetailsController {

    @RequestMapping(value = "/getPrincipal", method = RequestMethod.GET)
    public User getPrincipal(Authentication authentication) {
        User user= (User) authentication.getPrincipal();
        log.info("Principal- "+user);
        return user;
    }

    @RequestMapping(value = "/getAuthentication", method = RequestMethod.GET)
    public Authentication authentication(Authentication authentication) {
        log.info("Authentication- "+authentication);
        return authentication;
    }
}