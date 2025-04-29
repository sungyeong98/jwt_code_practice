package com.jwt_code_practice.global.security.jwt;

import java.util.Date;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import com.jwt_code_practice.domain.member.entity.Member;
import com.jwt_code_practice.domain.member.repository.MemberRepository;
import com.jwt_code_practice.global.config.redis.RedisRepository;
import com.jwt_code_practice.global.exception.ErrorCode;
import com.jwt_code_practice.global.exception.ServiceException;
import com.jwt_code_practice.global.security.oauth.model.OAuth2UserInfo;
import com.jwt_code_practice.global.security.oauth.service.OAuth2UserInfoFactory;
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
 *   <li>액세스 토큰 생성 - 일반 로그인 및 OAuth2 로그인 지원</li>
 *   <li>토큰에서 인증 정보 추출 - JWT 클레임에서 사용자 정보 파싱</li>
 *   <li>토큰 블랙리스트 관리 - 로그아웃 처리 및 토큰 무효화</li>
 * </ul>
 * </p>
 * <p>
 * 이 서비스는 {@link TokenUtilService}와 협력하여 토큰 관련 유틸리티 기능을 활용하고,
 * {@link RedisRepository}를 통해 토큰 블랙리스트를 관리합니다.
 * 또한 {@link CustomUserDetailsService}를 사용하여 토큰에서 추출한 사용자 ID를 기반으로
 * 사용자 상세 정보를 로드합니다.
 * </p>
 *
 * @author sungyeong98
 * @see TokenUtilService
 * @see RedisRepository
 * @see CustomUserDetailsService
 * @see Authentication
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AccessTokenService {
	private final CustomUserDetailsService userDetailsService;
	private final RedisRepository redisRepository;
	private final TokenUtilService tokenUtilService;
	private final MemberRepository memberRepository;

	/**
	 * 사용자 인증 정보를 기반으로 JWT 액세스 토큰을 생성합니다.
	 * <p>
	 * 이 메서드는 일반 로그인과 OAuth2 로그인 두 가지 인증 방식을 모두 지원합니다.
	 * 인증 객체의 Principal 타입에 따라 적절한 방식으로 토큰을 생성합니다.
	 * </p>
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
	 * <p>
	 * 일반 로그인의 경우 {@link CustomUserDetails}에서 사용자 정보를 추출하고,
	 * OAuth2 로그인의 경우 {@link OAuth2User}에서 이메일을 추출한 후 해당 이메일로
	 * 데이터베이스에서 사용자 정보를 조회하여 토큰을 생성합니다.
	 * </p>
	 *
	 * @param authentication 사용자 인증 정보 (일반 로그인 또는 OAuth2 로그인)
	 * @return 생성된 JWT 액세스 토큰 문자열
	 * @throws UsernameNotFoundException OAuth2 로그인 시 이메일로 사용자를 찾을 수 없는 경우
	 * @throws ServiceException 지원되지 않는 인증 방식인 경우 (NOT_SUPPORTED_OAUTH_LOGIN)
	 */
	public String createAccessToken(Authentication authentication) {
		long now = (new Date()).getTime();

		// Principal 타입에 따라 다르게 처리
		if (authentication.getPrincipal() instanceof CustomUserDetails) {
			// 일반 로그인의 경우
			CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

			return Jwts.builder()
				.claim("iss", tokenUtilService.getFrontend())
				.claim("sub", userDetails.getMemberInfo().getId())
				.claim("role", userDetails.getMemberInfo().getRole())
				.setIssuedAt(new Date(now))
				.setExpiration(new Date(now + tokenUtilService.getAccessTokenValidExpiration()))
				.signWith(tokenUtilService.getKey(), SignatureAlgorithm.HS512)
				.compact();
		} else if (authentication.getPrincipal() instanceof OAuth2User) {
			// OAuth2 로그인의 경우
			OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();

			// OAuth2User에서 필요한 정보 추출
			// 이메일을 기반으로 사용자 정보 조회
			String email = null;

			// OAuth2 제공자 확인 (Kakao, Google 등)
			if (authentication instanceof OAuth2AuthenticationToken) {
				String registrationId = ((OAuth2AuthenticationToken) authentication).getAuthorizedClientRegistrationId();

				// OAuth2UserInfo를 통해 이메일 정보 추출
				OAuth2UserInfo userInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(
					registrationId, oAuth2User.getAttributes());
				email = userInfo.getEmail();
			} else {
				// 기본 속성에서 이메일 추출 시도
				email = (String) oAuth2User.getAttributes().get("email");
			}

			// 이메일로 사용자 조회
			Optional<Member> memberOptional = memberRepository.findByEmail(email);

			if (memberOptional.isPresent()) {
				Member member = memberOptional.get();

				return Jwts.builder()
					.claim("iss", tokenUtilService.getFrontend())
					.claim("sub", member.getId())
					.claim("role", member.getMemberRole())
					.setIssuedAt(new Date(now))
					.setExpiration(new Date(now + tokenUtilService.getAccessTokenValidExpiration()))
					.signWith(tokenUtilService.getKey(), SignatureAlgorithm.HS512)
					.compact();
			} else {
				throw new UsernameNotFoundException("소셜 로그인 사용자 정보를 찾을 수 없습니다: " + email);
			}
		} else {
			throw new ServiceException(ErrorCode.NOT_SUPPORTED_OAUTH_LOGIN);
		}
	}

	/**
	 * JWT 토큰에서 인증 정보를 추출합니다.
	 * <p>
	 * 이 메서드는 다음과 같은 과정을 통해 토큰에서 인증 정보를 추출합니다:
	 * <ol>
	 *   <li>{@link TokenUtilService}를 사용하여 토큰의 서명을 검증하고 클레임을 추출</li>
	 *   <li>클레임에서 사용자 ID(sub)를 추출</li>
	 *   <li>{@link CustomUserDetailsService}를 통해 사용자 ID로 사용자 상세 정보 로드</li>
	 *   <li>로드된 사용자 정보와 권한을 기반으로 {@link UsernamePasswordAuthenticationToken} 생성</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 생성된 Authentication 객체는 Spring Security의 SecurityContext에 설정되어
	 * 인증된 사용자로서 보호된 리소스에 접근할 수 있게 합니다.
	 * </p>
	 * <p>
	 * 이 메서드는 주로 {@link com.jwt_code_practice.global.security.filter.JwtAuthorizationFilter}에서
	 * 요청에 포함된 토큰을 검증하고 인증 정보를 설정하는 데 사용됩니다.
	 * </p>
	 *
	 * @param token 검증 및 정보 추출 대상 JWT 토큰
	 * @return 토큰에서 추출한 사용자 인증 정보
	 * @throws io.jsonwebtoken.JwtException 토큰이 유효하지 않거나 만료된 경우
	 * @throws UsernameNotFoundException 토큰의 사용자 ID로 사용자를 찾을 수 없는 경우
	 */
	public Authentication getAuthentication(String token) {
		Claims claims = tokenUtilService.getClaims(token);

		CustomUserDetails userDetails = (CustomUserDetails) userDetailsService.loadUserByUsername(claims.getSubject());

		return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
	}

	/**
	 * 액세스 토큰을 블랙리스트에 등록합니다.
	 * <p>
	 * 이 메서드는 로그아웃 처리 또는 토큰 무효화가 필요한 경우 호출됩니다.
	 * 블랙리스트에 등록된 토큰은 유효한 서명을 가지고 있더라도 인증에 사용할 수 없습니다.
	 * </p>
	 * <p>
	 * 블랙리스트 등록 과정:
	 * <ol>
	 *   <li>Redis에서 기존 토큰 관련 데이터 제거</li>
	 *   <li>토큰의 남은 유효 기간 계산</li>
	 *   <li>토큰이 아직 유효한 경우, 남은 유효 기간 동안 블랙리스트에 등록</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 블랙리스트는 Redis에 "blacklist" + 토큰 문자열을 키로 하여 저장됩니다.
	 * 토큰의 남은 유효 기간이 만료되면 Redis에서 자동으로 제거되므로,
	 * 별도의 정리 작업이 필요하지 않습니다.
	 * </p>
	 * <p>
	 * 이 메서드는 주로 {@link com.jwt_code_practice.global.security.handler.CustomLogoutHandler}에서
	 * 사용자 로그아웃 처리 시 호출됩니다.
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
