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
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	private final JwtTokenProvider jwtTokenProvider;

	@Bean
	PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	/**
	 * Spring Security 필터 체인을 구성하고 반환합니다.
	 * <p>
	 * 이 메서드는 다음과 같은 보안 설정을 구성합니다:
	 * <ul>
	 *   <li>프레임 옵션: 동일 출처(same origin) 정책 적용</li>
	 *   <li>CSRF 보호: 비활성화 (REST API에서는 일반적으로 비활성화)</li>
	 *   <li>CORS: {@link #corsConfigurationSource()} 메서드를 통해 구성</li>
	 *   <li>세션 관리: STATELESS 정책 적용 (JWT 기반 인증을 위함)</li>
	 *   <li>URL 접근 제어: {@link SecurityConstants}에 정의된 공개 URL은 인증 없이 접근 가능,
	 *       그 외 모든 요청은 인증 필요</li>
	 * </ul>
	 * </p>
	 *
	 * @param http HttpSecurity 객체로, 보안 설정을 구성하는 데 사용됨
	 * @return 구성된 SecurityFilterChain 객체
	 * @throws Exception 보안 설정 구성 중 발생할 수 있는 예외
	 */
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authenticationManager) throws Exception {
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
				authorizeRequests.anyRequest().authenticated();
			})
			// JWT 필터 추가
			.addFilter(jwtAuthenticationFilter)
			.addFilterBefore(jwtAuthorizationFilter, UsernamePasswordAuthenticationFilter.class)
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
	 * 이 메서드는 다음과 같은 CORS 설정을 구성합니다:
	 * <ul>
	 *   <li>허용된 HTTP 메서드: GET, POST, PUT, PATCH, DELETE, OPTIONS</li>
	 *   <li>허용된 출처(Origin): http://localhost:3000 (프론트엔드 개발 서버)</li>
	 *   <li>자격 증명(Credentials) 허용: true (쿠키 및 인증 헤더 포함)</li>
	 *   <li>허용된 헤더: 모든 헤더 (*)</li>
	 *   <li>노출된 헤더: Authorization, Set-Cookie, Access-Control-Allow-Credentials
	 *       (클라이언트에서 접근 가능한 응답 헤더)</li>
	 * </ul>
	 * </p>
	 * <p>
	 * 모든 경로("/**")에 대해 위의 CORS 설정이 적용됩니다.
	 * </p>
	 *
	 * @return 구성된 UrlBasedCorsConfigurationSource 객체
	 */
	@Bean
	public UrlBasedCorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
		configuration.setAllowedOrigins(List.of("http://localhost:3000"));
		configuration.setAllowCredentials(true);
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setExposedHeaders(Arrays.asList("Authorization", "Set-Cookie", "Access-Control-Allow-Credentials"));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}
}
