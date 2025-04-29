package com.jwt_code_practice.global.security;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.jwt_code_practice.global.security.constants.SecurityConstants;
import com.jwt_code_practice.global.security.filter.JwtAuthenticationFilter;
import com.jwt_code_practice.global.security.filter.JwtAuthorizationFilter;
import com.jwt_code_practice.global.security.handler.CustomLogoutHandler;
import com.jwt_code_practice.global.security.jwt.JwtTokenProvider;
import com.jwt_code_practice.global.security.oauth.handler.OAuth2LoginSuccessHandler;
import com.jwt_code_practice.global.security.oauth.service.CustomOAuth2UserService;

import lombok.RequiredArgsConstructor;

/**
 * Spring Security 설정을 담당하는 클래스입니다.
 * <p>
 * 이 클래스는 애플리케이션의 보안 설정을 정의하며, 다음과 같은 주요 기능을 제공합니다:
 * <ul>
 *   <li>보안 필터 체인 구성</li>
 *   <li>CORS(Cross-Origin Resource Sharing) 설정</li>
 *   <li>세션 관리 정책 설정</li>
 *   <li>URL 기반 접근 제어 설정</li>
 *   <li>JWT 기반 인증 및 인가 필터 설정</li>
 *   <li>OAuth2 소셜 로그인 설정</li>
 *   <li>로그아웃 처리 설정</li>
 * </ul>
 * </p>
 * <p>
 * 이 클래스는 JWT 기반의 인증 시스템과 OAuth2 소셜 로그인을 통합하여
 * 사용자 인증을 처리합니다. 세션을 사용하지 않는 STATELESS 방식으로 설계되어
 * RESTful API 서버에 적합한 보안 구성을 제공합니다.
 * </p>
 * <p>
 * 주요 보안 컴포넌트:
 * <ul>
 *   <li>{@link JwtAuthenticationFilter}: 사용자 로그인 요청을 처리하고 JWT 토큰 발급</li>
 *   <li>{@link JwtAuthorizationFilter}: 요청에 포함된 JWT 토큰 검증 및 인증 정보 설정</li>
 *   <li>{@link CustomLogoutHandler}: 로그아웃 처리 및 토큰 무효화</li>
 *   <li>{@link CustomOAuth2UserService}: OAuth2 소셜 로그인 사용자 정보 처리</li>
 *   <li>{@link OAuth2LoginSuccessHandler}: OAuth2 로그인 성공 후 처리</li>
 * </ul>
 * </p>
 * <p>
 * {@link Configuration}과 {@link EnableWebSecurity} 어노테이션을 사용하여
 * Spring Security 설정 클래스임을 명시합니다.
 * </p>
 *
 * @author sungyeong98
 * @see SecurityFilterChain
 * @see HttpSecurity
 * @see SecurityConstants
 * @see JwtTokenProvider
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	private final JwtTokenProvider jwtTokenProvider;
	private final OAuth2LoginSuccessHandler oAuth2LoginSuccesshandler;

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	/**
	 * 인증 관리자를 제공하는 빈 메소드
	 * <p>
	 * 이 메소드는 Spring Security의 인증 프로세스를 관리하는
	 * {@link AuthenticationManager}를 생성하고 반환합니다.
	 * </p>
	 * <p>
	 * {@link AuthenticationManager}는 다음과 같은 역할을 수행합니다:
	 * <ul>
	 *   <li>사용자 인증 요청 처리</li>
	 *   <li>등록된 {@link org.springframework.security.authentication.AuthenticationProvider}를 통한 인증 위임</li>
	 *   <li>인증 성공/실패 결과 반환</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 빈은 주로 {@link JwtAuthenticationFilter}에 주입되어
	 * 사용자 로그인 요청을 처리하는 데 사용됩니다.
	 * </p>
	 *
	 * @param authenticationConfiguration 인증 설정 정보
	 * @return AuthenticationManager 인스턴스
	 * @throws Exception 인증 관리자 생성 중 오류 발생 시
	 * @see AuthenticationManager
	 * @see AuthenticationConfiguration
	 * @see JwtAuthenticationFilter
	 */
	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	/**
	 * Spring Security 필터 체인을 구성하고 반환합니다.
	 * <p>
	 * 이 메소드는 애플리케이션의 보안 설정을 정의하는 핵심 메소드로,
	 * JWT 기반 인증, OAuth2 소셜 로그인, CORS 설정, 접근 제어 등
	 * 다양한 보안 기능을 구성합니다.
	 * </p>
	 * <p>
	 * 주요 보안 설정:
	 * <ul>
	 *   <li><b>프레임 옵션:</b> 동일 출처(same origin) 정책 적용하여 클릭재킹 공격 방지</li>
	 *   <li><b>CSRF 보호:</b> 비활성화 (JWT 기반 인증에서는 일반적으로 불필요)</li>
	 *   <li><b>CORS:</b> {@link #corsConfigurationSource()} 메소드를 통해 크로스 오리진 요청 허용 설정</li>
	 *   <li><b>세션 관리:</b> STATELESS 정책 적용 (JWT 기반 인증을 위한 세션 미사용)</li>
	 *   <li><b>URL 접근 제어:</b> {@link SecurityConstants}에 정의된 공개 URL은 인증 없이 접근 가능,
	 *       그 외 모든 요청은 인증 필요</li>
	 *   <li><b>JWT 인증:</b> {@link JwtAuthenticationFilter}를 통한 로그인 처리 및 토큰 발급</li>
	 *   <li><b>JWT 인가:</b> {@link JwtAuthorizationFilter}를 통한 토큰 검증 및 인증 정보 설정</li>
	 *   <li><b>OAuth2 로그인:</b> {@link CustomOAuth2UserService}와 {@link OAuth2LoginSuccessHandler}를 통한 소셜 로그인 처리</li>
	 *   <li><b>로그아웃:</b> {@link CustomLogoutHandler}를 통한 로그아웃 처리 및 토큰 무효화</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 필터 체인 구성:
	 * <ol>
	 *   <li>{@link JwtAuthenticationFilter}: 로그인 요청 처리 및 JWT 토큰 발급</li>
	 *   <li>{@link JwtAuthorizationFilter}: JWT 토큰 검증 및 인증 정보 설정 (UsernamePasswordAuthenticationFilter 이후 실행)</li>
	 * </ol>
	 * </p>
	 * <p>
	 * 이 메소드는 Spring Boot 애플리케이션 시작 시 자동으로 호출되어
	 * 보안 설정을 초기화합니다.
	 * </p>
	 *
	 * @param http HttpSecurity 객체로, 보안 설정을 구성하는 데 사용됨
	 * @param authenticationManager 사용자 인증을 처리할 인증 관리자
	 * @param customOAuth2UserService OAuth2 사용자 정보를 처리할 서비스
	 * @return 구성된 SecurityFilterChain 객체
	 * @throws Exception 보안 설정 구성 중 발생할 수 있는 예외
	 * @see SecurityFilterChain
	 * @see HttpSecurity
	 * @see JwtAuthenticationFilter
	 * @see JwtAuthorizationFilter
	 * @see CustomOAuth2UserService
	 * @see OAuth2LoginSuccessHandler
	 * @see CustomLogoutHandler
	 */
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager,
		CustomOAuth2UserService customOAuth2UserService) throws Exception {
		// JWT 인증 필터 생성
		JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager, jwtTokenProvider);

		// JWT 인가 필터 생성
		JwtAuthorizationFilter jwtAuthorizationFilter = new JwtAuthorizationFilter(jwtTokenProvider);

		CustomLogoutHandler customLogoutHandler = new CustomLogoutHandler(jwtTokenProvider);

		http
			.headers(head -> head.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
			.csrf(AbstractHttpConfigurer::disable)
			.cors(cors -> cors.configurationSource(corsConfigurationSource()))
			.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
			.authorizeHttpRequests(authorizeRequests -> {
				Map<HttpMethod, List<String>> publicUrls = SecurityConstants.getPublicUrls();
				publicUrls.forEach((method, urls) -> 
					urls.forEach(url -> 
						authorizeRequests.requestMatchers(method, url).permitAll()
					)
				);
				authorizeRequests.requestMatchers("/error").permitAll();
				authorizeRequests.anyRequest().authenticated();
			})
			.addFilter(jwtAuthenticationFilter)
			.addFilterAfter(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
			.oauth2Login(oauth2 -> oauth2
				.userInfoEndpoint(userInfo -> userInfo
					.userService(customOAuth2UserService)
				)
				.successHandler(oAuth2LoginSuccesshandler)
			)
			.logout(logout -> logout
				.logoutUrl("/api/v1/logout")
				.addLogoutHandler(customLogoutHandler)
				.logoutSuccessHandler(customLogoutHandler)
			);

		return http.build();
	}

	/**
	 * CORS(Cross-Origin Resource Sharing) 설정을 구성하고 반환합니다.
	 * <p>
	 * 이 메소드는 다른 출처(origin)에서의 리소스 요청을 허용하기 위한
	 * CORS 정책을 설정합니다. 프론트엔드와 백엔드가 서로 다른 도메인이나 포트에서
	 * 실행될 때 필요한 설정입니다.
	 * </p>
	 * <p>
	 * 주요 CORS 설정:
	 * <ul>
	 *   <li><b>허용된 HTTP 메서드:</b> GET, POST, PUT, PATCH, DELETE, OPTIONS
	 *       <br>- 클라이언트가 서버에 요청할 수 있는 HTTP 메서드 지정</li>
	 *   <li><b>허용된 출처(Origin):</b> http://localhost:3000, http://localhost:8080
	 *       <br>- 프론트엔드 개발 서버 및 로컬 테스트 환경에서의 요청 허용</li>
	 *   <li><b>자격 증명(Credentials) 허용:</b> true
	 *       <br>- 쿠키, 인증 헤더, TLS 클라이언트 인증서를 포함한 요청 허용</li>
	 *   <li><b>허용된 헤더:</b> 모든 헤더 (*)
	 *       <br>- 클라이언트가 요청에 포함할 수 있는 모든 헤더 허용</li>
	 *   <li><b>노출된 헤더:</b> Authorization, Set-Cookie, Access-Control-Allow-Credentials
	 *       <br>- 클라이언트에서 접근 가능한 응답 헤더 지정 (JWT 토큰 및 쿠키 관련)</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 이 설정은 모든 경로("/**")에 적용되어, 애플리케이션의 모든 엔드포인트에
	 * 동일한 CORS 정책이 적용됩니다.
	 * </p>
	 * <p>
	 * 보안 고려사항:
	 * <ul>
	 *   <li>프로덕션 환경에서는 허용된 출처를 실제 프론트엔드 도메인으로 제한해야 함</li>
	 *   <li>필요한 HTTP 메서드만 허용하여 공격 표면 최소화</li>
	 *   <li>필요한 헤더만 노출하여 정보 유출 방지</li>
	 * </ul>
	 * </p>
	 *
	 * @return 구성된 UrlBasedCorsConfigurationSource 객체
	 * @see CorsConfiguration
	 * @see UrlBasedCorsConfigurationSource
	 */
	@Bean
	public UrlBasedCorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		configuration.setAllowedOrigins(Arrays.asList("http://localhost:3000", "http://localhost:8080"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setExposedHeaders(Arrays.asList("Authorization", "Set-Cookie", "Access-Control-Allow-Credentials"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
