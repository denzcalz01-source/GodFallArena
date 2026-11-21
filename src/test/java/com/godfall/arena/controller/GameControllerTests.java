package com.godfall.arena.controller;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.Cookie;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import tools.jackson.databind.ObjectMapper;

import com.godfall.arena.service.BackendJwtService;
import com.godfall.arena.service.FirebaseRestService;
import com.godfall.arena.service.FirebaseRestService.AccountBannedException;

class GameControllerTests {

	private BackendJwtService backendJwtService;
	private MockMvc mockMvc;

	@BeforeEach
	void setUp() {
		backendJwtService = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());
		mockMvc = MockMvcBuilders.standaloneSetup(
				new GameController(
						backendJwtService,
						new ClassPathResource("templates/game.html"),
						new ClassPathResource("templates/character-creation.html"),
						new ClassPathResource("templates/characters.html"),
						new ClassPathResource("templates/play.html")))
				.build();
	}

	@Test
	void redirectsToLoginWhenSessionCookieIsMissing() throws Exception {
		mockMvc.perform(get("/game"))
				.andExpect(status().isSeeOther())
				.andExpect(header().string("Location", "/?reason=session-ended"));
	}

	@Test
	void servesServerListForValidSession() throws Exception {
		String token = backendJwtService.issueUserToken("firebase-user-123");

		mockMvc.perform(get("/game").cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
				.andExpect(content().string(containsString("Choose your")))
				.andExpect(content().string(containsString("All servers")))
				.andExpect(content().string(containsString("/characters?serverId=")))
				.andExpect(content().string(org.hamcrest.Matchers.not(containsString("Back to characters"))));
	}

	@Test
	void characterCreationRequiresAnAuthenticatedSession() throws Exception {
		mockMvc.perform(get("/character-creation"))
				.andExpect(status().isSeeOther())
				.andExpect(header().string("Location", "/?reason=session-ended"));
	}

	@Test
	void servesCharacterCreationForValidSession() throws Exception {
		String token = backendJwtService.issueUserToken("firebase-user-123");

		mockMvc.perform(get("/character-creation")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
				.andExpect(content().string(containsString("Create your")));
	}

	@Test
	void characterSelectionRequiresAnAuthenticatedSession() throws Exception {
		mockMvc.perform(get("/characters"))
				.andExpect(status().isSeeOther())
				.andExpect(header().string("Location", "/?reason=session-ended"));
	}

	@Test
	void servesCharacterSelectionForValidSession() throws Exception {
		String token = backendJwtService.issueUserToken("firebase-user-123");

		mockMvc.perform(get("/characters")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
				.andExpect(content().string(containsString("Character roster")))
				.andExpect(content().string(containsString("/play?characterId=")))
				.andExpect(content().string(containsString("Delete character")));
	}

	@Test
	void gameplayRequiresAnAuthenticatedSession() throws Exception {
		mockMvc.perform(get("/play"))
				.andExpect(status().isSeeOther())
				.andExpect(header().string("Location", "/?reason=session-ended"));
	}

	@Test
	void servesGameplayPrototypeForValidSession() throws Exception {
		String token = backendJwtService.issueUserToken("firebase-user-123");

		mockMvc.perform(get("/play?characterId=character-123")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
				.andExpect(content().string(containsString("world-canvas")))
				.andExpect(content().string(containsString("worldPlayers")));
	}

	@Test
	void firebaseServerEndpointRequiresBackendSession() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();

		api.perform(get("/api/auth/servers")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token"))
				.andExpect(status().isUnauthorized());

		verifyNoInteractions(firebaseRestService);
	}

	@Test
	void firebaseServerEndpointReturnsOnlyAuthenticatedServerResults() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token"))
				.thenReturn(new FirebaseRestService.FirebaseAccount(
						"firebase-user-123", "warrior@example.com", true, "Warrior", true, true, true));
		when(firebaseRestService.getGameServers("firebase-id-token"))
				.thenReturn(List.of(new FirebaseRestService.GameServer("server-1", "Realm One", "online", true, 250)));
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(get("/api/auth/servers")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$[0].id").value("server-1"))
				.andExpect(jsonPath("$[0].name").value("Realm One"))
				.andExpect(jsonPath("$[0].recommended").value(true));
	}

	@Test
	void regularUsersCannotReadAllProfiles() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(get("/api/auth/users")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isForbidden());

		org.mockito.Mockito.verify(firebaseRestService, never()).getManagedUsers("firebase-id-token");
	}

	@Test
	void regularUsersCannotReadGameMasterActivity() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(get("/api/auth/gamemaster/activity")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isForbidden());

		org.mockito.Mockito.verify(firebaseRestService, never())
				.getGameMasterActivity("firebase-id-token", "firebase-user-123");
	}

	@Test
	void gameMastersCanReadTheirSeparateActivityFeed() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		when(firebaseRestService.getGameMasterActivity("firebase-id-token", "firebase-user-123"))
				.thenReturn(List.of(new FirebaseRestService.GameMasterActivity(
						"activity-1", "user_banned", "Warrior", "Banned account user-456 for 7 days.", 1_800_000_000_000L)));
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(get("/api/auth/gamemaster/activity")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$[0].event").value("user_banned"))
				.andExpect(jsonPath("$[0].target").value("Warrior"))
				.andExpect(jsonPath("$[0].details").value(containsString("7 days")));
	}

	@Test
	void regularUsersCannotReadCreatedCharactersAcrossAccounts() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(get("/api/auth/gamemaster/characters")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isForbidden());

		org.mockito.Mockito.verify(firebaseRestService, never()).getAllCharacters("firebase-id-token");
	}

	@Test
	void gameMastersCanReadCharactersCreatedAcrossServers() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		when(firebaseRestService.getAllCharacters("firebase-id-token"))
				.thenReturn(List.of(new FirebaseRestService.GameCharacter(
						"character-1",
						"firebase-user-456",
						"Astra",
						"server-1",
						"vanguard",
						"aetherborn",
						"masculine",
						"crown",
						"silver",
						"calm",
						1_800_000_000_000L,
						1234.5,
						876.25)));
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(get("/api/auth/gamemaster/characters")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$[0].uid").value("firebase-user-456"))
				.andExpect(jsonPath("$[0].serverId").value("server-1"))
				.andExpect(jsonPath("$[0].name").value("Astra"));
	}

	@Test
	void gameMastersCanReadProfilesAndCreateServers() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		when(firebaseRestService.getManagedUsers("firebase-id-token"))
				.thenReturn(List.of(new FirebaseRestService.ManagedUser(
						"firebase-user-456", "Warrior", "warrior@example.com", true, "user", 1_700_000_000_000L, null)));
		when(firebaseRestService.addGameServer("firebase-id-token", "Realm Two", "busy", true, 600))
				.thenReturn(new FirebaseRestService.GameServer("server-2", "Realm Two", "busy", true, 600));
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(get("/api/auth/users")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$[0].email").value("warrior@example.com"))
				.andExpect(jsonPath("$[0].role").value("user"))
				.andExpect(jsonPath("$[0].password").doesNotExist());

		api.perform(post("/api/auth/servers")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"name\":\"Realm Two\",\"status\":\"busy\",\"recommended\":true,\"maxUsers\":600}"))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.id").value("server-2"))
				.andExpect(jsonPath("$.name").value("Realm Two"))
				.andExpect(jsonPath("$.maxUsers").value(600));
		org.mockito.Mockito.verify(firebaseRestService).recordGameMasterActivity(
				"firebase-id-token",
				"firebase-user-123",
				"server_created",
				"Realm Two",
				"Created server server-2 with capacity setting 600.");
	}

	@Test
	void authenticatedPlayersCanSaveACharacterForASelectedServer() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		when(firebaseRestService.getGameServers("firebase-id-token"))
				.thenReturn(List.of(new FirebaseRestService.GameServer("server-1", "Realm One", "online", true, 250)));
		when(firebaseRestService.createCharacter(
				"firebase-id-token",
				"firebase-user-123",
				"Astra",
				"server-1",
				"vanguard",
				"aetherborn",
				"masculine",
				"crown",
				"silver",
				"calm"))
				.thenReturn(new FirebaseRestService.GameCharacter(
						"character-1",
						"firebase-user-123",
						"Astra",
						"server-1",
						"vanguard",
						"aetherborn",
						"masculine",
						"crown",
						"silver",
						"calm",
						null,
						null,
						null));
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(post("/api/auth/characters")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"name\":\"Astra\",\"serverId\":\"server-1\",\"classType\":\"vanguard\",\"lineage\":\"aetherborn\",\"bodyType\":\"masculine\",\"hairStyle\":\"crown\",\"hairColor\":\"silver\",\"faceStyle\":\"calm\"}"))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.name").value("Astra"))
				.andExpect(jsonPath("$.serverId").value("server-1"))
				.andExpect(jsonPath("$.classType").value("vanguard"));
	}

	@Test
	void duplicateCharacterNamesOnAServerReturnConflict() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		when(firebaseRestService.getGameServers("firebase-id-token"))
				.thenReturn(List.of(new FirebaseRestService.GameServer("server-1", "Realm One", "online", true, 250)));
		org.mockito.Mockito.doThrow(new FirebaseRestService.DuplicateCharacterNameException())
				.when(firebaseRestService).createCharacter(
						"firebase-id-token",
						"firebase-user-123",
						"Astra",
						"server-1",
						"vanguard",
						"aetherborn",
						"masculine",
						"crown",
						"silver",
						"calm");
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(post("/api/auth/characters")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"name\":\"Astra\",\"serverId\":\"server-1\",\"classType\":\"vanguard\",\"lineage\":\"aetherborn\",\"bodyType\":\"masculine\",\"hairStyle\":\"crown\",\"hairColor\":\"silver\",\"faceStyle\":\"calm\"}"))
				.andExpect(status().isConflict())
				.andExpect(jsonPath("$.message").value(containsString("already exists")));
	}

	@Test
	void playersCanOnlyLoadCharactersFromTheirOwnAccountPath() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		when(firebaseRestService.getCharacters("firebase-id-token", "firebase-user-123"))
				.thenReturn(List.of(new FirebaseRestService.GameCharacter(
						"character-1",
						"firebase-user-123",
						"Astra",
						"server-1",
						"vanguard",
						"aetherborn",
						"masculine",
						"crown",
						"silver",
						"calm",
						1_800_000_000_000L,
						null,
						null)));
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(get("/api/auth/characters")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$[0].uid").value("firebase-user-123"))
				.andExpect(jsonPath("$[0].name").value("Astra"))
				.andExpect(jsonPath("$[0].x").value(1234.5))
				.andExpect(jsonPath("$[0].y").value(876.25));
		org.mockito.Mockito.verify(firebaseRestService)
				.getCharacters("firebase-id-token", "firebase-user-123");
	}

	@Test
	void playersCanDeleteOnlyFromTheirAuthenticatedCharacterPath() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(delete("/api/auth/characters/{characterId}", "character-1")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isNoContent());

		org.mockito.Mockito.verify(firebaseRestService)
				.deleteCharacter("firebase-id-token", "firebase-user-123", "character-1");
	}

	@Test
	void bannedAccountsCannotCreateBackendSessions() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		doThrow(new AccountBannedException(1_800_000_000_000L))
				.when(firebaseRestService).saveProfileAndLogLogin(
						org.mockito.ArgumentMatchers.any(), eq("firebase-id-token"));
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();

		api.perform(post("/api/auth/session")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token"))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.message").value(containsString("banned until")));
	}

	@Test
	void activeBanBlocksAnExistingBackendSession() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		doThrow(new AccountBannedException(1_800_000_000_000L))
				.when(firebaseRestService).ensureNotBanned("firebase-user-123", "firebase-id-token");
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123");

		api.perform(get("/api/auth/servers")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.message").value(containsString("banned until")));
	}

	@Test
	void gameMastersCanBanAndEarlyUnbanUsers() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		when(firebaseRestService.getManagedUser("firebase-id-token", "firebase-user-456"))
				.thenReturn(new FirebaseRestService.ManagedUser(
						"firebase-user-456", "Warrior", "warrior@example.com", true, "user", null, null));
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(post("/api/auth/users/firebase-user-456/ban")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"durationDays\":365}"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.uid").value("firebase-user-456"))
				.andExpect(jsonPath("$.banUntil").isNumber());
		org.mockito.Mockito.verify(firebaseRestService).banUser(
				eq("firebase-id-token"), eq("firebase-user-456"), anyLong());
		org.mockito.Mockito.verify(firebaseRestService).recordGameMasterActivity(
				"firebase-id-token",
				"firebase-user-123",
				"user_banned",
				"Warrior",
				"Banned account firebase-user-456 for 365 days.");

		api.perform(post("/api/auth/users/firebase-user-456/unban")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isNoContent());
		org.mockito.Mockito.verify(firebaseRestService).unbanUser("firebase-id-token", "firebase-user-456");
		org.mockito.Mockito.verify(firebaseRestService).recordGameMasterActivity(
				"firebase-id-token",
				"firebase-user-123",
				"user_unbanned",
				"Warrior",
				"Cleared the ban for account firebase-user-456.");
	}

	@Test
	void banDurationOverOneYearIsRejected() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(post("/api/auth/users/firebase-user-456/ban")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"durationDays\":366}"))
				.andExpect(status().isBadRequest());

		org.mockito.Mockito.verify(firebaseRestService, never()).getManagedUser("firebase-id-token", "firebase-user-456");
	}

	@Test
	void serverCapacityMustBeBetweenOneAndOneHundredThousand() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(post("/api/auth/servers")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"name\":\"Realm\",\"status\":\"online\",\"recommended\":false,\"maxUsers\":100001}"))
				.andExpect(status().isBadRequest());

		org.mockito.Mockito.verify(firebaseRestService, never())
				.addGameServer("firebase-id-token", "Realm", "online", false, 100001);
	}

	@Test
	void gameMastersCanUpdateServerCapacity() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(patch("/api/auth/servers/server-1/capacity")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"maxUsers\":5000}"))
				.andExpect(status().isNoContent());
		org.mockito.Mockito.verify(firebaseRestService)
				.updateServerCapacity("firebase-id-token", "server-1", 5000);
	}

	@Test
	void gameMastersCanSetServerOnlineOrOffline() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(patch("/api/auth/servers/server-1/status")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"status\":\"offline\"}"))
				.andExpect(status().isNoContent());

		org.mockito.Mockito.verify(firebaseRestService).updateServerStatus(
				"firebase-id-token", "server-1", "offline");
		org.mockito.Mockito.verify(firebaseRestService).recordGameMasterActivity(
				"firebase-id-token",
				"firebase-user-123",
				"server_status_updated",
				"server-1",
				"Set server server-1 status to offline.");
	}

	@Test
	void serverStatusUpdateOnlyAcceptsOnlineOrOffline() throws Exception {
		FirebaseRestService firebaseRestService = mock(FirebaseRestService.class);
		when(firebaseRestService.verifyIdToken("firebase-id-token")).thenReturn(verifiedAccount());
		MockMvc api = MockMvcBuilders.standaloneSetup(
				new AuthController(firebaseRestService, backendJwtService, false))
				.build();
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		api.perform(patch("/api/auth/servers/server-1/status")
						.header(HttpHeaders.AUTHORIZATION, "Bearer firebase-id-token")
						.cookie(new Cookie(BackendJwtService.COOKIE_NAME, token))
						.contentType(MediaType.APPLICATION_JSON)
						.content("{\"status\":\"busy\"}"))
				.andExpect(status().isBadRequest());

		org.mockito.Mockito.verify(firebaseRestService, never())
				.updateServerStatus(org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.anyString());
	}

	private FirebaseRestService.FirebaseAccount verifiedAccount() {
		return new FirebaseRestService.FirebaseAccount(
				"firebase-user-123", "warrior@example.com", true, "Warrior", true, true, true);
	}
}
