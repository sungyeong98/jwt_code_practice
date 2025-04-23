package com.jwt_code_practice.global.security.filter;

import java.io.IOException;
import java.util.Objects;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwt_code_practice.global.security.jwt.JwtTokenProvider;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT 인가 필터
 * <p>
 * 이 필터는 모든 요청에 대해 JWT 토큰을 검증하고, 유효한 토큰이 있는 경우 인증 정보를 설정합니다.
 * </p>
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 필터 처리 메서드
     * <p>
     * 모든 요청에 대해 JWT 토큰을 검증하고, 유효한 토큰이 있는 경우 인증 정보를 설정합니다.
     * </p>
     * 
     * @param request HTTP 요청
     * @param response HTTP 응답
     * @param filterChain 필터 체인
     * @throws ServletException 서블릿 예외
     * @throws IOException IO 예외
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        
        // 요청에서 JWT 토큰 추출
        String token = jwtTokenProvider.extractToken(request);
        
        // 토큰이 유효한 경우 인증 정보 설정
        if (!Objects.isNull(token) && jwtTokenProvider.validateToken(token)) {
            Authentication authentication = jwtTokenProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            log.debug("Set Authentication to security context for '{}', uri: {}", 
                    authentication.getName(), request.getRequestURI());
        } else {
            log.debug("No valid JWT token found, uri: {}", request.getRequestURI());
        }
        
        filterChain.doFilter(request, response);
    }
}
