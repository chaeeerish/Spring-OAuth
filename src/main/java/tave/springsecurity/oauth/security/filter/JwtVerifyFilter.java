package tave.springsecurity.oauth.security.filter;

import com.google.gson.Gson;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.PatternMatchUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import tave.springsecurity.oauth.jwt.exception.CustomExpiredJwtException;
import tave.springsecurity.oauth.jwt.exception.CustomJwtException;
import tave.springsecurity.oauth.jwt.utils.JwtConstants;
import tave.springsecurity.oauth.jwt.utils.JwtUtils;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;

@Slf4j
public class JwtVerifyFilter extends OncePerRequestFilter {
    private static final String[] whitelist = {"/signUp", "/login" , "/refresh", "/", "/index.html"};

    private static void checkAuthorizationHeader(String header) {
        if (header == null) {
            throw new CustomJwtException("토큰이 전달되지 않았습니다");
        } else if (!header.startsWith(JwtConstants.JWT_TYPE)) {
            throw new CustomJwtException("BEARER 로 시작하지 않는 올바르지 않은 토큰 형식입니다");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String requestURI = request.getRequestURI();
        return PatternMatchUtils.simpleMatch(whitelist, requestURI);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader(JwtConstants.JWT_HEADER);

        try {
            checkAuthorizationHeader(authHeader);
            String token = JwtUtils.getTokenFromHeader(authHeader);
            Authentication authentication = JwtUtils.getAuthentication(token);

            SecurityContextHolder.getContext().setAuthentication(authentication);

            filterChain.doFilter(request, response);    // 다음 필터로 이동
        } catch (Exception e) {
            Gson gson = new Gson();
            String json = "";
            if (e instanceof CustomExpiredJwtException) {
                json = gson.toJson(Map.of("Token_Expired", e.getMessage()));
            } else {
                json = gson.toJson(Map.of("error", e.getMessage()));
            }

            response.setContentType("application/json; charset=UTF-8");
            PrintWriter printWriter = response.getWriter();
            printWriter.println(json);
            printWriter.close();
        }
    }
}
