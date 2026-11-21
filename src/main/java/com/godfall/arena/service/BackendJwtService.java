package com.godfall.arena.service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

@Service
public class BackendJwtService {

	public static final String COOKIE_NAME = "arena_session";
	public static final Duration TOKEN_LIFETIME = Duration.ofHours(1);

	private static final Logger logger = LoggerFactory.getLogger(BackendJwtService.class);
	private static final String ISSUER = "godfall-arena";
	private static final String SIGNING_ALGORITHM = "HmacSHA256";
	private static final Set<String> SUPPORTED_ROLES = Set.of("user", "gamemaster");
	private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
	private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
	private static final TypeReference<Map<String, Object>> CLAIMS_TYPE = new TypeReference<>() {};

	private final byte[] signingKey;
	private final ObjectMapper objectMapper;
	private final Map<String, String> activeSessionIds = new ConcurrentHashMap<>();

	public BackendJwtService(@Value("${app.jwt.secret:}") String configuredSecret, ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
		if (configuredSecret == null || configuredSecret.isBlank()) {
			signingKey = new byte[32];
			new SecureRandom().nextBytes(signingKey);
			logger.warn("APP_JWT_SECRET is unset; generated an ephemeral key. Set APP_JWT_SECRET to keep sessions valid across restarts.");
		} else {
			signingKey = configuredSecret.getBytes(StandardCharsets.UTF_8);
			if (signingKey.length < 32) {
				throw new IllegalArgumentException("APP_JWT_SECRET must be at least 32 bytes.");
			}
		}
	}

	public String issueUserToken(String uid) {
		return issueUserToken(uid, "user");
	}

	public String issueUserToken(String uid, String role) {
		if (uid == null || uid.isBlank() || role == null || !SUPPORTED_ROLES.contains(role)) {
			throw new IllegalArgumentException("A Firebase UID and supported session role are required.");
		}
		String sessionId = UUID.randomUUID().toString();
		activeSessionIds.put(uid, sessionId);
		return issueUserToken(uid, role, sessionId);
	}

	public String issueUserToken(String uid, String role, String sessionId) {
		if (sessionId == null || sessionId.isBlank()) {
			throw new IllegalArgumentException("A session ID is required.");
		}
		long issuedAt = Instant.now().getEpochSecond();
		Map<String, Object> header = Map.of("alg", "HS256", "typ", "JWT");
		Map<String, Object> claims = Map.of(
				"iss", ISSUER,
				"sub", uid,
				"uid", uid,
				"role", role,
				"sid", sessionId,
				"iat", issuedAt,
				"exp", issuedAt + TOKEN_LIFETIME.toSeconds());
		try {
			String unsignedToken = encodeJson(header) + "." + encodeJson(claims);
			return unsignedToken + "." + ENCODER.encodeToString(sign(unsignedToken));
		} catch (JacksonException exception) {
			throw new IllegalStateException("Could not create the backend session token.", exception);
		}
	}

	public SessionClaims verify(String token) {
		if (token == null) {
			throw new InvalidSessionTokenException();
		}
		String[] parts = token.split("\\.", -1);
		if (parts.length != 3) {
			throw new InvalidSessionTokenException();
		}

		try {
			Map<String, Object> header = decodeJson(parts[0]);
			if (!"HS256".equals(header.get("alg")) || !"JWT".equals(header.get("typ"))) {
				throw new InvalidSessionTokenException();
			}
			byte[] suppliedSignature = DECODER.decode(parts[2]);
			byte[] expectedSignature = sign(parts[0] + "." + parts[1]);
			if (!MessageDigest.isEqual(expectedSignature, suppliedSignature)) {
				throw new InvalidSessionTokenException();
			}

			Map<String, Object> claims = decodeJson(parts[1]);
			String uid = stringClaim(claims, "uid");
			String subject = stringClaim(claims, "sub");
			String role = stringClaim(claims, "role");
			String sessionId = stringClaim(claims, "sid");
			if (!ISSUER.equals(claims.get("iss"))
					|| !uid.equals(subject)
					|| !SUPPORTED_ROLES.contains(role)
					|| !sessionId.equals(activeSessionIds.get(uid))
					|| numberClaim(claims, "exp") <= Instant.now().getEpochSecond()) {
				throw new InvalidSessionTokenException();
			}
			return new SessionClaims(uid, role, sessionId);
		} catch (IllegalArgumentException | JacksonException exception) {
			throw new InvalidSessionTokenException();
		}
	}

	private String encodeJson(Object value) {
		return ENCODER.encodeToString(objectMapper.writeValueAsBytes(value));
	}

	private Map<String, Object> decodeJson(String value) {
		return objectMapper.readValue(DECODER.decode(value), CLAIMS_TYPE);
	}

	private byte[] sign(String value) {
		try {
			Mac mac = Mac.getInstance(SIGNING_ALGORITHM);
			mac.init(new SecretKeySpec(signingKey, SIGNING_ALGORITHM));
			return mac.doFinal(value.getBytes(StandardCharsets.US_ASCII));
		} catch (GeneralSecurityException exception) {
			throw new IllegalStateException("Could not sign the backend session token.", exception);
		}
	}

	private String stringClaim(Map<String, Object> claims, String name) {
		Object value = claims.get(name);
		if (!(value instanceof String stringValue) || stringValue.isBlank()) {
			throw new InvalidSessionTokenException();
		}
		return stringValue;
	}

	private long numberClaim(Map<String, Object> claims, String name) {
		Object value = claims.get(name);
		if (!(value instanceof Number number)) {
			throw new InvalidSessionTokenException();
		}
		return number.longValue();
	}

	public void revokeSession(String uid) {
		if (uid != null) {
			activeSessionIds.remove(uid);
		}
	}

	public record SessionClaims(String uid, String role, String sessionId) {}

	public static class InvalidSessionTokenException extends RuntimeException {}
}
