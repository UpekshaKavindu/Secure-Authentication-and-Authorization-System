package com.spring.security.utils;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

@Component
public class CookieUtil {
    @Value("${app.cookie.secure:true}")
    private boolean secure;

    @Value("${app.cookie.same-site:Strict}")
    private String sameSite;

    public void createAccessTokenCookie(HttpServletResponse response, String token, int maxAgeSeconds) {
        createCookie(response, "access_token", token, maxAgeSeconds);
    }

    public void createRefreshTokenCookie(HttpServletResponse response, String token, int maxAgeSeconds) {
        createCookie(response, "refresh_token", token, maxAgeSeconds);
    }

    private void createCookie(HttpServletResponse response, String name, String value, int maxAgeSeconds) {
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .path("/")
                .maxAge(maxAgeSeconds)
                .sameSite(sameSite)
                .build();
        response.addHeader("Set-Cookie", cookie.toString());
    }

    public void clearCookies(HttpServletResponse response) {
        createCookie(response, "access_token", "", 0);
        createCookie(response, "refresh_token", "", 0);
    }

    public String getAccessTokenFromCookies(HttpServletRequest request) {
        return getCookieValue(request, "access_token");
    }

    public String getRefreshTokenFromCookies(HttpServletRequest request) {
        return getCookieValue(request, "refresh_token");
    }

    private String getCookieValue(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
