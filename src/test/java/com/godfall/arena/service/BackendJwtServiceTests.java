package com.godfall.arena.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

import tools.jackson.databind.ObjectMapper;

class BackendJwtServiceTests {

	@Test
	void issuesAndVerifiesUserClaims() {
		BackendJwtService service = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());

		BackendJwtService.SessionClaims claims = service.verify(service.issueUserToken("firebase-user-123"));

		assertEquals("firebase-user-123", claims.uid());
		assertEquals("user", claims.role());
	}

	@Test
	void issuesAndVerifiesGameMasterClaims() {
		BackendJwtService service = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());

		BackendJwtService.SessionClaims claims =
				service.verify(service.issueUserToken("firebase-user-123", "gamemaster"));

		assertEquals("gamemaster", claims.role());
	}

	@Test
	void rejectsUnsupportedSessionRole() {
		BackendJwtService service = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());

		assertThrows(
				IllegalArgumentException.class,
				() -> service.issueUserToken("firebase-user-123", "administrator"));
	}

	@Test
	void rejectsTamperedToken() {
		BackendJwtService service = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());
		String token = service.issueUserToken("firebase-user-123");
		String signatureAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		int signatureLastCharacter = signatureAlphabet.indexOf(token.charAt(token.length() - 1));
		String tamperedToken = token.substring(0, token.length() - 1)
				+ signatureAlphabet.charAt(signatureLastCharacter | 1);

		assertThrows(
				BackendJwtService.InvalidSessionTokenException.class,
				() -> service.verify(tamperedToken));
	}

	@Test
	void rejectsSessionReplacedByAnotherLogin() {
		BackendJwtService service = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());
		String firstDeviceToken = service.issueUserToken("firebase-user-123");

		service.issueUserToken("firebase-user-123");

		assertThrows(
				BackendJwtService.InvalidSessionTokenException.class,
				() -> service.verify(firstDeviceToken));
	}

	@Test
	void refreshPreservesActiveSession() {
		BackendJwtService service = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());
		String token = service.issueUserToken("firebase-user-123");
		BackendJwtService.SessionClaims claims = service.verify(token);

		String refreshedToken = service.issueUserToken(claims.uid(), claims.role(), claims.sessionId());

		assertEquals(claims, service.verify(refreshedToken));
	}

	@Test
	void revokedSessionIsRejected() {
		BackendJwtService service = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());
		String token = service.issueUserToken("firebase-user-123");

		service.revokeSession("firebase-user-123");

		assertThrows(
				BackendJwtService.InvalidSessionTokenException.class,
				() -> service.verify(token));
	}
}
