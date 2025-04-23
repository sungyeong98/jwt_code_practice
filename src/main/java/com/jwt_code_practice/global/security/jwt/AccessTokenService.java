package com.jwt_code_practice.global.security.jwt;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import com.jwt_code_practice.global.config.redis.RedisRepository;
import com.jwt_code_practice.global.security.user.CustomUserDetails;
import com.jwt_code_practice.global.security.user.CustomUserDetailsService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 액세스 토큰 관련 기능을 제공하는 서비스 클래스입니다.
 * <p>
 * 이 클래스는 JWT 액세스 토큰의 생성, 검증, 추출 및 블랙리스트 관리 기능을 담당합니다.
 * Spring Security의 인증 체계와 통합되어 사용자 인증 정보를 토큰으로 변환하고,
 * 토큰에서 인증 정보를 추출하는 역할을 수행합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>액세스 토큰 생성</li>
 *   <li>토큰에서 인증 정보 추출</li>
 *   <li>HTTP 요청에서 액세스 토큰 추출</li>
 *   <li>로그아웃 시 토큰 블랙리스트 관리</li>
 * </ul>
 * </p>
 *
 * @author sungyeong98
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccessTokenService {
	private final CustomUserDetailsService userDetailsService;
	private final RedisRepository redisRepository;
	private final TokenUtilService tokenUtilService;

	/**
	 * 사용자 인증 정보를 기반으로 JWT 액세스 토큰을 생성합니다.
	 * <p>
	 * 생성된 토큰에는 다음 정보가 포함됩니다:
	 * <ul>
	 *   <li>발행자(iss): 프론트엔드 도메인</li>
	 *   <li>주제(sub): 사용자 ID</li>
	 *   <li>역할(role): 사용자 권한</li>
	 *   <li>발행 시간(iat): 현재 시간</li>
	 *   <li>만료 시간(exp): 현재 시간 + 설정된 만료 기간</li>
	 * </ul>
	 * </p>
	 *
	 * @param authentication 사용자 인증 정보
	 * @return 생성된 JWT 액세스 토큰 문자열
	 */
	public String createAccessToken(Authentication authentication) {
		CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

		long now = (new Date()).getTime();

		return Jwts.builder()
			.claim("iss", tokenUtilService.getFrontend())
			.claim("sub", userDetails.getMemberInfo().getId())
			.claim("role", userDetails.getMemberInfo().getRole())
			.setIssuedAt(new Date(now))
			.setExpiration(new Date(now + tokenUtilService.getAccessTokenValidExpiration()))
			.signWith(tokenUtilService.getKey(), SignatureAlgorithm.HS512)
			.compact();
	}

	/**
	 * JWT 토큰에서 인증 정보를 추출합니다.
	 * <p>
	 * 토큰의 서명을 검증하고, 페이로드에서 사용자 ID를 추출하여 해당 사용자의
	 * 상세 정보를 로드합니다. 로드된 사용자 정보를 기반으로 Spring Security에서
	 * 사용할 수 있는 Authentication 객체를 생성하여 반환합니다.
	 * </p>
	 *
	 * @param token 검증 및 정보 추출 대상 JWT 토큰
	 * @return 토큰에서 추출한 사용자 인증 정보
	 * @throws io.jsonwebtoken.JwtException 토큰이 유효하지 않거나 만료된 경우
	 */
	public Authentication getAuthentication(String token) {
		Claims claims = tokenUtilService.getClaims(token);

		CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(claims.getSubject());

		return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	}

	/**
	 * 액세스 토큰을 블랙리스트에 등록합니다.
	 * <p>
	 * 로그아웃 또는 토큰 무효화가 필요한 경우 호출됩니다. 기존 토큰을 Redis에서 제거하고,
	 * 토큰의 남은 유효 기간 동안 블랙리스트에 등록하여 재사용을 방지합니다.
	 * 블랙리스트에 등록된 토큰은 유효한 서명을 가지고 있더라도 인증에 사용할 수 없습니다.
	 * </p>
	 *
	 * @param accessToken 블랙리스트에 등록할 액세스 토큰
	 */
	public void setBlackList(String accessToken) {
		try {
			redisRepository.remove(accessToken);

			long expiration = tokenUtilService.getExpiration(accessToken).getTime() - System.currentTimeMillis();

			if (expiration > 0) {
				redisRepository.save("blacklist" + accessToken, "logout", expiration, TimeUnit.MILLISECONDS);
			}
			log.info("토큰 블랙리스트 등록 성공");
		} catch (Exception e) {
			log.error("토큰 블랙리스트 등록 과정 중 오류 발생", e);
		}
	}
}
