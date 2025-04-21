package com.jwt_code_practice.global.security;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
	/**
	 * SecurityFilterChain를 생성하여 반환하는 메서드
	 * @param http HttpSecurity
	 * @return {@link SecurityFilterChain} SecurityFilterChain
	 * @throws Exception 예외
	 */
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
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
			});
		return http.build();
	}

	/**
	 * CorsConfigurationSource를 생성하여 반환하는 메서드
	 * <p>
	 *		허용할 HTTP 메서드 설정 ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS") <br>
	 *		CORS 설정 ("http://localhost:3000") <br>
	 *		자격 증명 허용 <br>
	 *		모든 헤더 설정 ("*")
	 * </p>
	 * @return {@link UrlBasedCorsConfigurationSource} UrlBasedCorsConfigurationSource
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
