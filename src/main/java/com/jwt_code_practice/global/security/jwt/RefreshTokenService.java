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
 *   <li>리프레시 토큰 생성 - JWT 형식의 리프레시 토큰 생성</li>
 *   <li>액세스 토큰과 리프레시 토큰 매핑 정보 저장 - Redis에 키-값 쌍으로 저장</li>
 * </ul>
 * </p>
 * <p>
 * 이 서비스는 다음 컴포넌트들과 협력하여 동작합니다:
 * <ul>
 *   <li>{@link RedisRepository}: 토큰 매핑 정보를 저장하고 관리하는 Redis 저장소</li>
 *   <li>{@link TokenUtilService}: 토큰 생성 및 검증에 필요한 설정 정보와 유틸리티 기능 제공</li>
 *   <li>{@link JwtTokenProvider}: 전체 JWT 인증 시스템을 관리하는 상위 컴포넌트</li>
 * </ul>
 * </p>
 * <p>
 * 리프레시 토큰 메커니즘은 다음과 같은 보안 이점을 제공합니다:
 * <ul>
 *   <li>액세스 토큰의 유효 기간을 짧게 유지하여 탈취 시 피해 최소화</li>
 *   <li>사용자가 자격 증명을 다시 입력하지 않고도 새로운 액세스 토큰 발급 가능</li>
 *   <li>액세스 토큰과 리프레시 토큰의 분리를 통한 보안 강화</li>
 * </ul>
 * </p>
 * <p>
 * 일반적인 사용 흐름:
 * <ol>
 *   <li>사용자 로그인 시 액세스 토큰과 리프레시 토큰 모두 발급</li>
 *   <li>액세스 토큰은 클라이언트에 쿠키로 전달, 리프레시 토큰은 서버에 저장</li>
 *   <li>액세스 토큰 만료 시 클라이언트는 리프레시 토큰을 사용하여 새 액세스 토큰 요청</li>
 *   <li>서버는 리프레시 토큰의 유효성을 검증하고 새 액세스 토큰 발급</li>
 * </ol>
 * </p>
 *
 * @author sungyeong98
 * @see JwtTokenProvider
 * @see AccessTokenService
 * @see TokenUtilService
 * @see RedisRepository
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
	 * 이 메소드는 다음과 같은 과정으로 리프레시 토큰을 생성합니다:
	 * <ol>
	 *   <li>현재 시간 정보 획득</li>
	 *   <li>JWT 빌더를 사용하여 토큰 클레임 설정</li>
	 *   <li>토큰 서명 알고리즘 및 키 설정</li>
	 *   <li>최종 JWT 문자열 생성</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 생성된 토큰에는 다음 정보가 포함됩니다:
	 * <ul>
	 *   <li>발행자(iss): 프론트엔드 도메인 - 토큰을 발행한 시스템 식별</li>
	 *   <li>발행 시간(iat): 현재 시간 - 토큰이 생성된 시점</li>
	 *   <li>만료 시간(exp): 현재 시간 + 설정된 만료 기간 - 토큰의 유효 기간</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 리프레시 토큰은 액세스 토큰과 달리 사용자 ID나 권한 정보를 포함하지 않습니다.
	 * 이는 리프레시 토큰의 목적이 단순히 새로운 액세스 토큰을 발급받기 위한 것이기 때문입니다.
	 * 리프레시 토큰은 액세스 토큰보다 긴 유효 기간을 가지며, 일반적으로 다음과 같은 값이 사용됩니다:
	 * <ul>
	 *   <li>액세스 토큰: 15분 ~ 1시간</li>
	 *   <li>리프레시 토큰: 1일 ~ 2주</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 {@link JwtTokenProvider#saveToken} 메소드에서 호출되어
	 * 사용자 로그인 시 리프레시 토큰을 생성하는 데 사용됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * // 사용자 로그인 성공 시
	 * String accessToken = accessTokenService.createAccessToken(authentication);
	 * String refreshToken = refreshTokenService.createRefreshToken();
	 *
	 * // 토큰 매핑 정보 저장
	 * refreshTokenService.saveRefreshToken(accessToken, refreshToken);
	 * </pre>
	 * </p>
	 *
	 * @return 생성된 JWT 리프레시 토큰 문자열
	 * @see JwtTokenProvider#saveToken
	 * @see io.jsonwebtoken.JwtBuilder
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
	 * 이 메소드는 다음과 같은 과정으로 토큰 매핑 정보를 저장합니다:
	 * <ol>
	 *   <li>액세스 토큰을 키로 사용</li>
	 *   <li>리프레시 토큰을 값으로 저장</li>
	 *   <li>리프레시 토큰의 유효 기간을 만료 시간으로 설정</li>
	 *   <li>Redis에 키-값 쌍 저장</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 액세스 토큰을 키로 사용하고 리프레시 토큰을 값으로 저장함으로써,
	 * 클라이언트가 제공한 액세스 토큰에 대응하는 리프레시 토큰을 빠르게 조회할 수 있습니다.
	 * 이 매핑 정보는 리프레시 토큰의 유효 기간 동안 유지되며, 유효 기간이 지나면
	 * Redis에서 자동으로 제거됩니다.
	 * </p>
	 * <p>
	 * 저장된 매핑 정보는 다음과 같은 경우에 활용됩니다:
	 * <ul>
	 *   <li>액세스 토큰 갱신 요청 시 리프레시 토큰의 유효성 검증</li>
	 *   <li>로그아웃 시 리프레시 토큰 무효화</li>
	 *   <li>토큰 재발급 시 이전 토큰 매핑 정보 확인</li>
	 * </ul>
	 * </p>
	 * <p>
	 * Redis를 사용하여 토큰 매핑 정보를 저장함으로써 다음과 같은 이점이 있습니다:
	 * <ul>
	 *   <li>빠른 조회 성능 (O(1) 시간 복잡도)</li>
	 *   <li>자동 만료 기능을 통한 메모리 관리</li>
	 *   <li>분산 환경에서의 토큰 정보 공유</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 메소드는 주로 {@link JwtTokenProvider#saveToken} 메소드에서 호출되어
	 * 사용자 로그인 성공 후 생성된 토큰들의 매핑 정보를 저장하는 데 사용됩니다.
	 * </p>
	 * <p>
	 * 예시 코드:
	 * <pre>
	 * // 사용자 로그인 성공 시
	 * String accessToken = accessTokenService.createAccessToken(authentication);
	 * String refreshToken = refreshTokenService.createRefreshToken();
	 *
	 * // 토큰 매핑 정보 저장
	 * refreshTokenService.saveRefreshToken(accessToken, refreshToken);
	 *
	 * // 클라이언트에 액세스 토큰 전달
	 * response.addHeader("Set-Cookie", cookieService.setCookie("_at", accessToken));
	 * </pre>
	 * </p>
	 *
	 * @param accessToken 액세스 토큰 (Redis의 키로 사용)
	 * @param refreshToken 리프레시 토큰 (Redis의 값으로 저장)
	 * @see JwtTokenProvider#saveToken
	 * @see RedisRepository#save
	 */
	public void saveRefreshToken(String accessToken, String refreshToken) {
		redisRepository.save(accessToken, refreshToken, tokenUtilService.getRefreshTokenValidExpiration(), TimeUnit.MILLISECONDS);
	}
}
