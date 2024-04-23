package tave.springsecurity.oauth.jwt.controller;


import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tave.springsecurity.oauth.jwt.exception.CustomJwtException;
import tave.springsecurity.oauth.jwt.utils.JwtConstants;
import tave.springsecurity.oauth.jwt.utils.JwtUtils;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class JwtController {
    @RequestMapping("/refresh")
    public Map<String, Object> refresh(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null) {
            throw new CustomJwtException("Access Token 이 존재하지 않습니다");
        } else if (!authHeader.startsWith(JwtConstants.JWT_TYPE)) {
            throw new CustomJwtException("BEARER 로 시작하지 않는 올바르지 않은 토큰 형식입니다");
        }

        String refreshToken = JwtUtils.getTokenFromHeader(authHeader);
        Map<String, Object> claims = JwtUtils.validateToken(refreshToken);
        String newAccessToken = JwtUtils.generateToken(claims, JwtConstants.ACCESS_EXP_TIME);

        String newRefreshToken = refreshToken;
        newRefreshToken = JwtUtils.generateToken(claims, JwtConstants.REFRESH_EXP_TIME);

        return Map.of("accessToken", newAccessToken, "refreshToken", newRefreshToken);
    }
}