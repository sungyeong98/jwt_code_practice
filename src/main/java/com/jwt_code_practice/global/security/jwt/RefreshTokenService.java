package com.jwt_code_practice.global.security.jwt;

import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.springframework.stereotype.Service;

import com.jwt_code_practice.global.config.redis.RedisRepository;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * 리프레시 토큰 관련 기능을 제공하는 서비스 클래스입니다.
 * <p>
 * 이 클래스는 JWT 리프레시 토큰의 생성 및 저장 기능을 담당합니다.
 * 리프레시 토큰은 액세스 토큰이 만료되었을 때 새로운 액세스 토큰을 발급받기 위해 사용됩니다.
 * Redis를 활용하여 액세스 토큰과 리프레시 토큰 간의 매핑 정보를 저장하고 관리합니다.
 * </p>
 * <p>
 * 주요 기능:
 * <ul>
 *   <li>리프레시 토큰 생성</li>
 *   <li>액세스 토큰과 리프레시 토큰 매핑 정보 저장</li>
 * </ul>
 * </p>
 *
 * @author sungyeong98
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
	private final RedisRepository redisRepository;
	private final TokenUtilService tokenUtilService;

	/**
	 * 새로운 JWT 리프레시 토큰을 생성합니다.
	 * <p>
	 * 생성된 토큰에는 다음 정보가 포함됩니다:
	 * <ul>
	 *   <li>발행자(iss): 프론트엔드 도메인</li>
	 *   <li>발행 시간(iat): 현재 시간</li>
	 *   <li>만료 시간(exp): 현재 시간 + 설정된 만료 기간</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 리프레시 토큰은 액세스 토큰보다 긴 유효 기간을 가지며, 사용자 정보를 포함하지 않고
	 * 단순히 새로운 액세스 토큰을 발급받기 위한 용도로만 사용됩니다.
	 * </p>
	 *
	 * @return 생성된 JWT 리프레시 토큰 문자열
	 */
	public String createRefreshToken() {
		long now = (new Date()).getTime();

		return Jwts.builder()
			.claim("iss", tokenUtilService.getFrontend())
			.setIssuedAt(new Date(now))
			.setExpiration(new Date(now + tokenUtilService.getRefreshTokenValidExpiration()))
			.signWith(tokenUtilService.getKey(), SignatureAlgorithm.HS512)
			.compact();
	}

	/**
	 * 액세스 토큰과 리프레시 토큰의 매핑 정보를 Redis에 저장합니다.
	 * <p>
	 * 액세스 토큰을 키로 사용하고 리프레시 토큰을 값으로 저장합니다.
	 * 이 매핑 정보는 리프레시 토큰의 유효 기간 동안 유지되며, 액세스 토큰이 만료되었을 때
	 * 클라이언트가 제공한 리프레시 토큰의 유효성을 검증하는 데 사용됩니다.
	 * </p>
	 * <p>
	 * 저장된 매핑 정보는 다음과 같은 경우에 활용됩니다:
	 * <ul>
	 *   <li>액세스 토큰 갱신 요청 시 리프레시 토큰의 유효성 검증</li>
	 *   <li>로그아웃 시 리프레시 토큰 무효화</li>
	 * </ul>
	 * </p>
	 *
	 * @param accessToken 액세스 토큰 (Redis의 키로 사용)
	 * @param refreshToken 리프레시 토큰 (Redis의 값으로 저장)
	 */
	public void saveRefreshToken(String accessToken, String refreshToken) {
		redisRepository.save(accessToken, refreshToken, tokenUtilService.getRefreshTokenValidExpiration(), TimeUnit.MILLISECONDS);
	}
}
