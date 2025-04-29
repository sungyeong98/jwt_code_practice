package com.jwt_code_practice.global.security.jwt;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.Objects;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import com.jwt_code_practice.global.config.redis.RedisRepository;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * JWT 토큰 관련 유틸리티 기능을 제공하는 서비스 클래스입니다.
 * <p>
 * 이 클래스는 JWT 토큰의 생성, 파싱, 검증에 필요한 공통 기능과 설정 정보를 제공합니다.
 * 토큰 서명에 사용되는 비밀 키를 관리하고, 토큰의 유효 기간 설정을 제공하며,
 * 토큰 블랙리스트 확인 등의 기능을 담당합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>JWT 토큰 서명에 사용되는 비밀 키 초기화 및 관리</li>
 *   <li>JWT 토큰 파싱 및 클레임 추출</li>
 *   <li>토큰 만료 시간 확인</li>
 *   <li>토큰 유효성 검증</li>
 *   <li>토큰 블랙리스트 확인</li>
 * </ul>
 * </p>
 * <p>
 * 이 서비스는 다음 컴포넌트들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link AccessTokenService}: 액세스 토큰 생성 및 검증</li>
 *   <li>{@link RefreshTokenService}: 리프레시 토큰 생성 및 관리</li>
 *   <li>{@link JwtTokenProvider}: JWT 인증 시스템 전체 관리</li>
 *   <li>{@link RedisRepository}: 토큰 블랙리스트 저장 및 조회</li>
 * </ul>
 * </p>
 * <p>
 * 이 클래스는 환경 변수나 설정 파일에서 다음과 같은 설정 값을 로드합니다:
 * <ul>
 *   <li>JWT_SECRET: 토큰 서명에 사용되는 비밀 키</li>
 *   <li>JWT_ACCESS_EXPIRATION: 액세스 토큰의 유효 기간 (밀리초)</li>
 *   <li>JWT_REFRESH_EXPIRATION: 리프레시 토큰의 유효 기간 (밀리초)</li>
 *   <li>frontend: 프론트엔드 도메인 (토큰 발행자 정보)</li>
 * </ul>
 * </p>
 * <p>
 * 보안 관련 고려사항:
 * <ul>
 *   <li>비밀 키는 충분히 길고 복잡해야 하며, 안전하게 관리되어야 합니다.</li>
 *   <li>액세스 토큰의 유효 기간은 보안과 사용자 경험 사이의 균형을 고려하여 설정해야 합니다.</li>
 *   <li>토큰 블랙리스트는 로그아웃된 토큰이 재사용되는 것을 방지하는 중요한 보안 메커니즘입니다.</li>
 * </ul>
 * </p>
 *
 * @author sungyeong98
 * @see JwtTokenProvider
 * @see AccessTokenService
 * @see RefreshTokenService
 * @see RedisRepository
 */
@Getter
@Component
@RequiredArgsConstructor
public class TokenUtilService {
	private final RedisRepository redisRepository;

	private Key key;

	@Value("${JWT_SECRET}")
	private String secretKey;

	@Value("${JWT_ACCESS_EXPIRATION}")
	private long accessTokenValidExpiration;

	@Value("${JWT_REFRESH_EXPIRATION}")
	private long refreshTokenValidExpiration;

	@Value("${frontend}")
	private String frontend;

	@PostConstruct
	public void init() {
		this.key = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
	}

	/**
	 * JWT 토큰을 파싱하여 클레임을 추출합니다.
	 * <p>
	 * 이 메소드는 JWT 토큰 문자열을 파싱하여 서명을 검증하고,
	 * 토큰의 페이로드에 포함된 클레임(Claims)을 추출합니다.
	 * </p>
	 * <p>
	 * 파싱 과정:
	 * <ol>
	 *   <li>JWT 파서 빌더 생성</li>
	 *   <li>서명 검증에 사용할 키 설정</li>
	 *   <li>JWT 파서 빌드</li>
	 *   <li>토큰 파싱 및 서명 검증</li>
	 *   <li>검증된 토큰의 클레임 반환</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 이 메소드는 다음과 같은 경우에 예외를 발생시킬 수 있습니다:
	 * <ul>
	 *   <li>{@link io.jsonwebtoken.ExpiredJwtException}: 토큰이 만료된 경우</li>
	 *   <li>{@link io.jsonwebtoken.MalformedJwtException}: 토큰 형식이 잘못된 경우</li>
	 *   <li>{@link io.jsonwebtoken.SignatureException}: 토큰 서명이 유효하지 않은 경우</li>
	 *   <li>{@link io.jsonwebtoken.UnsupportedJwtException}: 지원되지 않는 JWT 형식인 경우</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 클래스 내부에서만 사용되는 private 메소드로,
	 * {@link #getClaims(String)}와 {@link #getExpiration(String)} 메소드에서 호출됩니다.
	 * </p>
	 *
	 * @param token 파싱할 JWT 토큰 문자열
	 * @return 토큰에서 추출한 클레임 객체
	 * @throws io.jsonwebtoken.JwtException 토큰 파싱 또는 검증 실패 시
	 * @see io.jsonwebtoken.Jwts#parserBuilder()
	 * @see io.jsonwebtoken.Claims
	 */
	private Claims parseToken(String token) {
		return Jwts.parserBuilder()
			.setSigningKey(key)
			.build()
			.parseClaimsJws(token)
			.getBody();
	}

	/**
	 * JWT 토큰에서 클레임을 추출합니다.
	 * <p>
	 * 이 메소드는 {@link #parseToken(String)} 메소드를 호출하여
	 * JWT 토큰을 파싱하고 클레임을 추출합니다.
	 * </p>
	 * <p>
	 * 추출된 클레임에는 다음과 같은 정보가 포함될 수 있습니다:
	 * <ul>
	 *   <li>iss (발행자): 토큰을 발행한 시스템</li>
	 *   <li>sub (주제): 토큰의 주제 (일반적으로 사용자 ID)</li>
	 *   <li>role (역할): 사용자의 권한 정보</li>
	 *   <li>iat (발행 시간): 토큰이 발행된 시간</li>
	 *   <li>exp (만료 시간): 토큰이 만료되는 시간</li>
	 *   <li>기타 커스텀 클레임</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 {@link AccessTokenService#getAuthentication(String)} 메소드에서
	 * 호출되어 토큰에서 사용자 ID를 추출하는 데 사용됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * Claims claims = tokenUtilService.getClaims(token);
	 * String userId = claims.getSubject();
	 * String role = claims.get("role", String.class);
	 * </pre>
	 * </p>
	 *
	 * @param token 클레임을 추출할 JWT 토큰
	 * @return 토큰에서 추출한 클레임 객체
	 * @throws io.jsonwebtoken.JwtException 토큰 파싱 또는 검증 실패 시
	 * @see #parseToken(String)
	 * @see io.jsonwebtoken.Claims
	 */
	public Claims getClaims(String token) {
		return parseToken(token);
	}

	/**
	 * JWT 토큰의 만료 시간을 추출합니다.
	 * <p>
	 * 이 메소드는 {@link #parseToken(String)} 메소드를 호출하여
	 * JWT 토큰을 파싱하고, 토큰의 만료 시간(exp) 클레임을 추출합니다.
	 * </p>
	 * <p>
	 * 추출된 만료 시간은 다음과 같은 용도로 사용될 수 있습니다:
	 * <ul>
	 *   <li>토큰의 남은 유효 기간 계산</li>
	 *   <li>토큰 갱신 시점 결정</li>
	 *   <li>블랙리스트 등록 시 만료 시간 설정</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 {@link AccessTokenService#setBlackList(String)} 메소드에서
	 * 호출되어 블랙리스트에 등록할 토큰의 남은 유효 기간을 계산하는 데 사용됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * Date expiration = tokenUtilService.getExpiration(token);
	 * long remainingTime = expiration.getTime() - System.currentTimeMillis();
	 *
	 * if (remainingTime > 0) {
	 *     // 토큰이 아직 유효한 경우의 처리
	 *     redisRepository.save("blacklist" + token, "logout", remainingTime, TimeUnit.MILLISECONDS);
	 * }
	 * </pre>
	 * </p>
	 *
	 * @param token 만료 시간을 추출할 JWT 토큰
	 * @return 토큰의 만료 시간을 나타내는 Date 객체
	 * @throws io.jsonwebtoken.JwtException 토큰 파싱 또는 검증 실패 시
	 * @see #parseToken(String)
	 * @see io.jsonwebtoken.Claims#getExpiration()
	 */
	public Date getExpiration(String token) {
		return parseToken(token).getExpiration();
	}

	/**
	 * JWT 토큰의 유효성을 검증합니다.
	 * <p>
	 * 이 메소드는 다음과 같은 검증을 수행합니다:
	 * <ol>
	 *   <li>토큰이 null이 아닌지 확인</li>
	 *   <li>토큰이 블랙리스트에 등록되지 않았는지 확인</li>
	 *   <li>토큰 파싱 및 서명 검증 (예외 처리를 통해)</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 이 메소드는 다음과 같은 경우에 false를 반환합니다:
	 * <ul>
	 *   <li>토큰이 null인 경우</li>
	 *   <li>토큰이 블랙리스트에 등록된 경우</li>
	 *   <li>토큰 파싱 또는 서명 검증에 실패한 경우 (예외 발생)</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 토큰 파싱 및 서명 검증 과정에서 발생할 수 있는 예외:
	 * <ul>
	 *   <li>{@link io.jsonwebtoken.ExpiredJwtException}: 토큰이 만료된 경우</li>
	 *   <li>{@link io.jsonwebtoken.MalformedJwtException}: 토큰 형식이 잘못된 경우</li>
	 *   <li>{@link io.jsonwebtoken.SignatureException}: 토큰 서명이 유효하지 않은 경우</li>
	 *   <li>{@link io.jsonwebtoken.UnsupportedJwtException}: 지원되지 않는 JWT 형식인 경우</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 {@link JwtTokenProvider#validateToken(String)} 메소드에서 호출되어
	 * 요청에 포함된 토큰의 유효성을 검증하는 데 사용됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * String token = jwtTokenProvider.extractToken(request);
	 *
	 * if (token != null && tokenUtilService.validateToken(token)) {
	 *     // 유효한 토큰인 경우의 처리
	 *     Authentication authentication = jwtTokenProvider.getAuthentication(token);
	 *     SecurityContextHolder.getContext().setAuthentication(authentication);
	 * }
	 * </pre>
	 * </p>
	 *
	 * @param token 유효성을 검증할 JWT 토큰
	 * @return 토큰이 유효하면 true, 그렇지 않으면 false
	 * @see #isTokenBlackListed(String)
	 * @see JwtTokenProvider#validateToken(String)
	 */
	public boolean validateToken(String token) {
		if (Objects.isNull(token)) {
			return false;
		}
		try {
			return !isTokenBlackListed(token);
		} catch (Exception e) {
			return false;
		}
	}

	/**
	 * JWT 토큰이 블랙리스트에 등록되었는지 확인합니다.
	 * <p>
	 * 이 메소드는 Redis에 저장된 토큰 블랙리스트를 조회하여
	 * 주어진 토큰이 블랙리스트에 등록되었는지 확인합니다.
	 * </p>
	 * <p>
	 * 블랙리스트 확인 과정:
	 * <ol>
	 *   <li>"blacklist" + 토큰 문자열을 키로 하여 Redis에서 값 조회</li>
	 *   <li>조회된 값이 null이 아니면 블랙리스트에 등록된 것으로 판단</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 토큰 블랙리스트는 다음과 같은 경우에 사용됩니다:
	 * <ul>
	 *   <li>사용자 로그아웃 시 토큰 무효화</li>
	 *   <li>토큰 탈취 감지 시 강제 무효화</li>
	 *   <li>비밀번호 변경 시 기존 토큰 무효화</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 {@link #validateToken(String)} 메소드에서 호출되어
	 * 토큰의 블랙리스트 여부를 확인하는 데 사용됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * if (tokenUtilService.isTokenBlackListed(token)) {
	 *     // 블랙리스트에 등록된 토큰인 경우의 처리
	 *     throw new InvalidTokenException("로그아웃된 토큰입니다.");
	 * }
	 * </pre>
	 * </p>
	 *
	 * @param token 블랙리스트 여부를 확인할 JWT 토큰
	 * @return 토큰이 블랙리스트에 등록되었으면 true, 그렇지 않으면 false
	 * @see RedisRepository#get(String)
	 * @see AccessTokenService#setBlackList(String)
	 */
	public boolean isTokenBlackListed(String token) {
		Object value = redisRepository.get("blacklist" + token);

		return !Objects.isNull(value);
	}
}
