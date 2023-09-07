package com.spring.securityPractice.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.spring.securityPractice.SpringApplicationContext;
import com.spring.securityPractice.constants.AppConstants;
import com.spring.securityPractice.model.UserDto;
import com.spring.securityPractice.model.UserLoginRequestModel;
import com.spring.securityPractice.service.UserService;
import com.spring.securityPractice.utils.JWTUtils;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.NoSuchElementException;

@RequiredArgsConstructor
@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            UserLoginRequestModel creds = new ObjectMapper().readValue(request.getInputStream(), UserLoginRequestModel.class);
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(creds.getEmail(), creds.getPassword())
            );
        } catch (IOException | InternalAuthenticationServiceException e) {
            log.info("Exception occurred at attemptAuthentication method: {}", e.getLocalizedMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            try {
                response.getWriter().write("Authentication failed: Please provide proper input data!");
                response.getWriter().flush();
            } catch (IOException ex) {
                return null;
            }
            return null;
        }
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        String user = ((User)authResult.getPrincipal()).getUsername();
        String accessToken = JWTUtils.generateToken(user);
        UserService userService = (UserService) SpringApplicationContext.getBean("userServiceImpl");
        UserDto userDto = userService.getUser(user);
//        response.addHeader("userId",userDto.getUserId());
//        response.addHeader(AppConstants.HEADER_STRING,AppConstants.TOKEN_PREFIX+accessToken);
        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("userId", userDto.getUserId());
        responseBody.put("accessToken", accessToken);

        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(responseBody);

        response.setContentType("application/json");
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                              AuthenticationException failed) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        try {
            throw failed;
        } catch (BadCredentialsException e) {
            response.getWriter().write("Authentication failed: Email or password is incorrect!");
        } catch (LockedException e) {
            response.getWriter().write("Authentication failed: Account is locked");
        } catch (DisabledException e) {
            response.getWriter().write("Authentication failed: Account is disabled");
        } catch (AccountExpiredException e) {
            response.getWriter().write("Authentication failed: Account has expired");
        } catch (NoSuchElementException e) {
            response.getWriter().write("Authentication failed: Please provide the required fields");
        }

        response.getWriter().flush();
    }


}
