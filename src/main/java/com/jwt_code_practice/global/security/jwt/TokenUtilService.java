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

	private Claims parseToken(String token) {
		return Jwts.parserBuilder()
			.setSigningKey(key)
			.build()
			.parseClaimsJws(token)
			.getBody();
	}

	public Claims getClaims(String token) {
		return parseToken(token);
	}

	public Date getExpiration(String token) {
		return parseToken(token).getExpiration();
	}

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

	public boolean isTokenBlackListed(String token) {
		Object value = redisRepository.get("blacklist" + token);

		return !Objects.isNull(value);
	}
}
