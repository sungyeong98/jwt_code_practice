package com.jwt_code_practice.global.security.filter;

import static com.jwt_code_practice.global.security.constants.SecurityConstants.*;

import java.io.IOException;
import java.util.Objects;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import com.jwt_code_practice.global.security.constants.SecurityConstants;
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
 * 이 필터는 Spring Security 필터 체인에서 모든 HTTP 요청에 대해 JWT 토큰을 검증하고,
 * 유효한 토큰이 있는 경우 해당 사용자의 인증 정보를 SecurityContext에 설정합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>모든 HTTP 요청에 대해 JWT 토큰 검증</li>
 *   <li>공개 URL에 대한 요청은 인증 과정 생략</li>
 *   <li>유효한 토큰이 있는 경우 SecurityContext에 인증 정보 설정</li>
 *   <li>인증 정보가 설정된 요청은 Spring Security의 권한 검사 메커니즘을 통과할 수 있음</li>
 * </ul>
 * </p>
 * <p>
 * 이 필터는 {@link OncePerRequestFilter}를 확장하여 각 요청에 대해 한 번만 실행되도록 보장합니다.
 * 또한 {@link SecurityConstants}에 정의된 공개 URL 패턴에 대해서는 필터 처리를 건너뛰어
 * 인증 없이도 접근할 수 있도록 합니다.
 * </p>
 * <p>
 * 이 필터는 주로 {@link JwtTokenProvider}와 협력하여 토큰 추출, 검증 및 인증 정보 생성을 수행합니다.
 * </p>
 *
 * @see JwtTokenProvider
 * @see SecurityConstants
 * @see OncePerRequestFilter
 * @see SecurityContextHolder
 */
@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final JwtTokenProvider jwtTokenProvider;

    /**
     * 필터 처리 메서드
     * <p>
     * 이 메서드는 모든 HTTP 요청에 대해 다음과 같은 작업을 수행합니다:
     * <ol>
     *   <li>HTTP 요청에서 JWT 토큰 추출</li>
     *   <li>추출된 토큰의 유효성 검증</li>
     *   <li>토큰이 유효한 경우, 토큰에서 사용자 인증 정보 추출</li>
     *   <li>추출된 인증 정보를 SecurityContext에 설정</li>
     *   <li>다음 필터로 요청 전달</li>
     * </ol>
     * </p>
     * <p>
     * 토큰이 없거나 유효하지 않은 경우에도 요청은 다음 필터로 전달되지만,
     * SecurityContext에 인증 정보가 설정되지 않아 보호된 리소스에 접근할 수 없습니다.
     * </p>
     * <p>
     * 이 메서드는 {@link #shouldNotFilter(HttpServletRequest)} 메서드에 의해
     * 필터링이 필요하지 않다고 판단된 요청에 대해서는 실행되지 않습니다.
     * </p>
     *
     * @param request 현재 HTTP 요청
     * @param response 현재 HTTP 응답
     * @param filterChain 다음 필터로 요청을 전달하기 위한 필터 체인
     * @throws ServletException 필터 처리 중 서블릿 관련 오류 발생 시
     * @throws IOException 필터 처리 중 I/O 관련 오류 발생 시
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        log.debug("인증 필터 동작 중...");

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

    /**
     * 필터 적용 여부 결정 메서드
     * <p>
     * 이 메서드는 현재 HTTP 요청이 필터를 적용해야 하는지 여부를 결정합니다.
     * {@link SecurityConstants}에 정의된 공개 URL 패턴과 일치하는 요청에 대해서는
     * 필터 처리를 건너뛰어 인증 없이도 접근할 수 있도록 합니다.
     * </p>
     * <p>
     * 이 메서드가 true를 반환하면 {@link #doFilterInternal(HttpServletRequest, HttpServletResponse, FilterChain)}
     * 메서드는 실행되지 않고, 요청은 바로 다음 필터로 전달됩니다.
     * </p>
     * <p>
     * 주로 다음과 같은 URL에 대해 필터를 적용하지 않습니다:
     * <ul>
     *   <li>로그인 및 회원가입 API</li>
     *   <li>OAuth2 인증 관련 URL</li>
     *   <li>H2 콘솔 접근 URL</li>
     *   <li>기타 {@link SecurityConstants}에 정의된 공개 URL</li>
     * </ul>
     * </p>
     *
     * @param request 현재 HTTP 요청
     * @return 필터를 적용하지 않아야 하면 true, 적용해야 하면 false
     * @throws ServletException 필터 적용 여부 결정 중 오류 발생 시
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        log.info("전체 공개 url로 인증 과정을 스킵합니다.");
        return isPublicUrl(request);
    }

    /**
     * 공개 URL 여부 확인 메서드
     * <p>
     * 이 메서드는 현재 HTTP 요청의 URI와 HTTP 메서드가 {@link SecurityConstants}에 정의된
     * 공개 URL 패턴과 일치하는지 확인합니다.
     * </p>
     * <p>
     * URL 패턴 매칭은 Spring의 {@link AntPathMatcher}를 사용하여 수행됩니다.
     * 이를 통해 와일드카드(*)를 포함한 패턴 매칭이 가능합니다.
     * </p>
     * <p>
     * 예를 들어, "/api/v1/login"이나 "/h2-console/**"와 같은 패턴과 일치하는 요청은
     * 공개 URL로 간주됩니다.
     * </p>
     *
     * @param request 현재 HTTP 요청
     * @return 요청이 공개 URL 패턴과 일치하면 true, 그렇지 않으면 false
     */
    private boolean isPublicUrl(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        HttpMethod method = HttpMethod.valueOf(request.getMethod());

        var patterns = getPublicUrls().get(method);

        return patterns != null && patterns.stream()
            .anyMatch(pattern -> new AntPathMatcher().match(pattern, requestUri));
    }
}
