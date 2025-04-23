package com.jwt_code_practice.global.security.jwt;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * JWT 토큰 생성 및 검증을 담당하는 클래스입니다.
 * <p>
 * 이 클래스는 JWT 기반 인증 시스템의 핵심 컴포넌트로, 다음과 같은 주요 기능을 제공합니다:
 * <ul>
 *   <li>사용자 인증 정보를 기반으로 JWT 액세스 토큰 및 리프레시 토큰 생성</li>
 *   <li>HTTP 요청에서 JWT 토큰 추출</li>
 *   <li>JWT 토큰의 유효성 검증</li>
 *   <li>JWT 토큰에서 사용자 인증 정보 추출</li>
 *   <li>로그아웃 시 토큰 무효화 및 쿠키 삭제</li>
 * </ul>
 * </p>
 * <p>
 * 이 클래스는 다음 서비스들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link AccessTokenService}: 액세스 토큰 생성, 검증 및 관리</li>
 *   <li>{@link RefreshTokenService}: 리프레시 토큰 생성 및 관리</li>
 *   <li>{@link CookieService}: HTTP 쿠키 생성 및 관리</li>
 * </ul>
 * </p>
 * <p>
 * 이 클래스는 Spring Security 필터 체인과 통합되어 인증 및 권한 부여 프로세스를 처리합니다.
 * </p>
 *
 * @author sungyeong98
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {
    private final AccessTokenService accessTokenService;
    private final RefreshTokenService refreshTokenService;
    private final CookieService cookieService;
    private final TokenUtilService tokenUtilService;

    /**
     * 인증 정보를 기반으로 JWT 토큰을 생성하고 HTTP 응답에 설정합니다.
     * <p>
     * 이 메소드는 다음과 같은 작업을 수행합니다:
     * <ol>
     *   <li>사용자 인증 정보를 기반으로 JWT 액세스 토큰 생성</li>
     *   <li>새로운 리프레시 토큰 생성</li>
     *   <li>액세스 토큰을 HTTP 쿠키로 설정</li>
     *   <li>액세스 토큰과 리프레시 토큰의 매핑 정보를 Redis에 저장</li>
     *   <li>생성된 쿠키를 HTTP 응답 헤더에 추가</li>
     * </ol>
     * </p>
     * <p>
     * 이 메소드는 주로 로그인 성공 시 호출되어 클라이언트에게 인증 토큰을 제공합니다.
     * 생성된 액세스 토큰은 HTTP Only 쿠키로 설정되어 JavaScript에서 접근할 수 없으며,
     * HTTPS 연결에서만 전송되도록 Secure 속성이 적용됩니다.
     * </p>
     *
     * @param authentication 사용자 인증 정보 (Spring Security의 Authentication 객체)
     * @param response HTTP 응답 객체에 쿠키를 설정하기 위한 파라미터
     */
    public void saveToken(Authentication authentication, HttpServletResponse response) {
        String accessToken = accessTokenService.createAccessToken(authentication);
        String refreshToken = refreshTokenService.createRefreshToken();

        String token = cookieService.setCookie("_at", accessToken);

        refreshTokenService.saveRefreshToken(accessToken, refreshToken);
        response.addHeader("Set-Cookie", token);
    }

    /**
     * 사용자의 토큰을 삭제하고 블랙리스트에 등록합니다.
     * <p>
     * 이 메소드는 다음과 같은 작업을 수행합니다:
     * <ol>
     *   <li>HTTP 요청에서 액세스 토큰 추출</li>
     *   <li>추출된 액세스 토큰을 블랙리스트에 등록하여 재사용 방지</li>
     *   <li>클라이언트의 액세스 토큰 쿠키를 삭제하기 위한 만료된 쿠키 생성</li>
     *   <li>생성된 만료 쿠키를 HTTP 응답 헤더에 추가</li>
     * </ol>
     * </p>
     * <p>
     * 이 메소드는 주로 로그아웃 요청 처리 시 호출되어 사용자의 인증 상태를 종료합니다.
     * 블랙리스트에 등록된 토큰은 유효 기간이 남아있더라도 더 이상 인증에 사용할 수 없습니다.
     * </p>
     *
     * @param request 쿠키에서 액세스 토큰을 추출하기 위한 HTTP 요청 객체
     * @param response 쿠키를 삭제하기 위한 HTTP 응답 객체
     */
    public void deleteToken(HttpServletRequest request, HttpServletResponse response) {
        String accessToken = cookieService.extractToken(request);

        accessTokenService.setBlackList(accessToken);

        String token = cookieService.deleteCookie("_at", accessToken);

        response.addHeader("Set-Cookie", token);
    }

    /**
     * JWT 토큰에서 인증 정보를 추출합니다.
     * <p>
     * 이 메소드는 다음과 같은 작업을 수행합니다:
     * <ol>
     *   <li>JWT 토큰의 서명 검증</li>
     *   <li>토큰 페이로드에서 사용자 ID 추출</li>
     *   <li>사용자 ID를 기반으로 사용자 상세 정보 로드</li>
     *   <li>사용자 정보와 권한을 포함한 Authentication 객체 생성</li>
     * </ol>
     * </p>
     * <p>
     * 이 메소드는 주로 보호된 리소스에 대한 요청 처리 전에 호출되어
     * 요청에 포함된 토큰의 유효성을 검증하고 사용자 인증 정보를 추출합니다.
     * 추출된 인증 정보는 Spring Security의 SecurityContext에 설정되어
     * 애플리케이션 전체에서 현재 인증된 사용자 정보로 사용됩니다.
     * </p>
     *
     * @param token 인증 정보를 추출할 JWT 토큰
     * @return 토큰에서 추출한 사용자 인증 정보 (Spring Security의 Authentication 객체)
     * @throws io.jsonwebtoken.JwtException 토큰이 유효하지 않거나 만료된 경우
     */
    public Authentication getAuthentication(String token) {
        return accessTokenService.getAuthentication(token);
    }

    /**
     * HTTP 요청에서 JWT 토큰을 추출합니다.
     * <p>
     * 이 메소드는 HTTP 요청의 쿠키 중 "_at" 이름을 가진 쿠키의 값을
     * JWT 액세스 토큰으로 추출합니다. 쿠키가 없거나 "_at" 쿠키가 없는 경우
     * null을 반환합니다.
     * </p>
     * <p>
     * 이 메소드는 주로 JWT 인증 필터에서 호출되어 요청에 포함된 토큰을
     * 추출하고 검증하는 과정의 첫 단계로 사용됩니다.
     * </p>
     *
     * @param request JWT 토큰을 추출할 HTTP 요청
     * @return 추출된 JWT 토큰, 없으면 null
     */
    public String extractToken(HttpServletRequest request) {
        return cookieService.extractToken(request);
    }

    /**
     * JWT 토큰의 유효성을 검증합니다.
     * <p>
     * 이 메소드는 다음과 같은 검증을 수행합니다:
     * <ul>
     *   <li>토큰 서명의 유효성 검증</li>
     *   <li>토큰 만료 여부 확인</li>
     *   <li>토큰 형식의 유효성 검증</li>
     * </ul>
     * </p>
     * <p>
     * 검증은 AccessTokenService의 getAuthentication 메소드를 호출하여 수행됩니다.
     * 이 메소드가 예외 없이 성공적으로 반환되면 토큰이 유효한 것으로 간주합니다.
     * 검증 과정에서 예외가 발생하면 로그에 오류를 기록하고 false를 반환합니다.
     * </p>
     * <p>
     * 이 메소드는 주로 JWT 인증 필터에서 호출되어 요청에 포함된 토큰의
     * 유효성을 검증하는 데 사용됩니다.
     * </p>
     *
     * @param token 유효성을 검증할 JWT 토큰
     * @return 토큰이 유효하면 true, 그렇지 않으면 false
     */
    public boolean validateToken(String token) {
        return tokenUtilService.validateToken(token);
    }
}
