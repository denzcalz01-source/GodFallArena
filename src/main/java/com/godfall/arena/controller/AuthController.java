package com.godfall.arena.controller;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.beans.factory.annotation.Value;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.godfall.arena.service.BackendJwtService;
import com.godfall.arena.service.FirebaseRestService;
import com.godfall.arena.service.FirebaseRestService.AccountBannedException;
import com.godfall.arena.service.FirebaseRestService.CharacterNotFoundException;
import com.godfall.arena.service.FirebaseRestService.DashboardData;
import com.godfall.arena.service.FirebaseRestService.DatabasePermissionException;
import com.godfall.arena.service.FirebaseRestService.DuplicateCharacterNameException;
import com.godfall.arena.service.FirebaseRestService.FirebaseAccount;
import com.godfall.arena.service.FirebaseRestService.FirebaseUnavailableException;
import com.godfall.arena.service.FirebaseRestService.GameCharacter;
import com.godfall.arena.service.FirebaseRestService.GameMasterActivity;
import com.godfall.arena.service.FirebaseRestService.GameMasterActivityWriteException;
import com.godfall.arena.service.FirebaseRestService.GameServer;
import com.godfall.arena.service.FirebaseRestService.InvalidCharacterDataException;
import com.godfall.arena.service.FirebaseRestService.InvalidGameMasterActivityDataException;
import com.godfall.arena.service.FirebaseRestService.InvalidFirebaseTokenException;
import com.godfall.arena.service.FirebaseRestService.InvalidManagedUserDataException;
import com.godfall.arena.service.FirebaseRestService.InvalidProfileRoleException;
import com.godfall.arena.service.FirebaseRestService.InvalidServerDataException;
import com.godfall.arena.service.FirebaseRestService.ManagedUser;
import com.godfall.arena.service.FirebaseRestService.ProfileNotFoundException;
import com.godfall.arena.service.FirebaseRestService.UserProfile;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

	private static final Logger logger = LoggerFactory.getLogger(AuthController.class);
	private static final Set<String> SERVER_STATUSES = Set.of("online", "busy", "full", "offline");
	private static final Set<String> SERVER_AVAILABILITY_STATUSES = Set.of("online", "offline");
	private static final Set<String> CHARACTER_CLASSES = Set.of("vanguard", "striker", "arcanist", "warden");
	private static final Set<String> CHARACTER_LINEAGES = Set.of("aetherborn", "stoneborn", "wildkin");
	private static final Set<String> CHARACTER_BODY_TYPES = Set.of("masculine", "feminine");
	private static final Set<String> CHARACTER_HAIR_STYLES = Set.of("crown", "spire", "nomad", "aegis");
	private static final Set<String> CHARACTER_HAIR_COLORS = Set.of("silver", "gold", "ember", "violet");
	private static final Set<String> CHARACTER_FACE_STYLES = Set.of("calm", "focused", "battle-ready");
	private static final int MAX_SERVER_USERS = 100_000;
	private static final int MAX_BAN_DAYS = 365;

	private final FirebaseRestService firebaseRestService;
	private final BackendJwtService backendJwtService;
	private final boolean secureAuthCookie;

	public AuthController(
			FirebaseRestService firebaseRestService,
			BackendJwtService backendJwtService,
			@Value("${app.auth-cookie-secure:false}") boolean secureAuthCookie) {
		this.firebaseRestService = firebaseRestService;
		this.backendJwtService = backendJwtService;
		this.secureAuthCookie = secureAuthCookie;
	}

	@PostMapping("/session")
	public ResponseEntity<?> createSession(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
		String idToken = getIdToken(authorization);
		if (idToken == null) {
			logger.debug("Rejected auth session request without a Firebase ID token");
			return error(HttpStatus.UNAUTHORIZED, "A Firebase ID token is required.");
		}

		try {
			FirebaseAccount account = firebaseRestService.verifyIdToken(idToken);
			if (!account.emailVerified()) {
				logger.warn("Rejected auth session for an unverified Firebase account");
				return error(HttpStatus.FORBIDDEN, "Verify your email before signing in.");
			}
			if (!hasValidDatabaseClaims(account)) {
				logDatabaseClaimMismatch(account);
				return error(
						HttpStatus.UNAUTHORIZED,
						"Firebase verified the account, but the ID token claims are stale or belong to another project. Sign out, then sign in again.");
			}
			UserProfile user = firebaseRestService.saveProfileAndLogLogin(account, idToken);
			String sessionToken = backendJwtService.issueUserToken(user.uid(), user.role());
			logger.info("Firebase auth session established");
			return ResponseEntity.ok()
					.header(HttpHeaders.SET_COOKIE, authCookie(sessionToken, BackendJwtService.TOKEN_LIFETIME).toString())
					.header(HttpHeaders.SET_COOKIE, legacyAuthCookie().toString())
					.body(Map.of("message", "Signed in.", "user", user));
		} catch (InvalidFirebaseTokenException exception) {
			logger.warn("Rejected auth session with an invalid Firebase ID token");
			return error(HttpStatus.UNAUTHORIZED, "The Firebase ID token is invalid or expired.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(
					HttpStatus.FORBIDDEN,
					"Realtime Database rejected the " + exception.operation()
							+ " (HTTP " + exception.statusCode()
							+ "). Confirm the current database.rules.json is published under Realtime Database > Rules and that the Firebase ID token is verified.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while establishing an auth session: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		} catch (InvalidProfileRoleException exception) {
			logger.error("Firebase profile has an unsupported role");
			return error(HttpStatus.BAD_GATEWAY, "The account profile contains an unsupported role.");
		} catch (AccountBannedException exception) {
			return error(HttpStatus.FORBIDDEN, accountBannedMessage(exception));
		}
	}

	@GetMapping("/session")
	public ResponseEntity<?> validateSession(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		String idToken = getIdToken(authorization);
		if (idToken == null) {
			return error(HttpStatus.UNAUTHORIZED, "A Firebase ID token is required.");
		}

		try {
			BackendJwtService.SessionClaims session = backendJwtService.verify(sessionToken);
			FirebaseAccount account = firebaseRestService.verifyIdToken(idToken);
			if (!account.emailVerified()) {
				return error(HttpStatus.FORBIDDEN, "Verify your email before opening the dashboard.");
			}
			if (!hasValidDatabaseClaims(account) || !session.uid().equals(account.uid())) {
				return error(HttpStatus.UNAUTHORIZED, "The sign-in session is invalid. Sign in again.");
			}
			UserProfile user = firebaseRestService.getUserProfile(account.uid(), idToken);
			String refreshedSessionToken =
					backendJwtService.issueUserToken(user.uid(), user.role(), session.sessionId());
			return ResponseEntity.ok()
					.header(HttpHeaders.SET_COOKIE, authCookie(refreshedSessionToken, BackendJwtService.TOKEN_LIFETIME).toString())
					.header(HttpHeaders.SET_COOKIE, legacyAuthCookie().toString())
					.body(Map.of("authenticated", true, "uid", user.uid(), "role", user.role()));
		} catch (BackendJwtService.InvalidSessionTokenException exception) {
			return error(HttpStatus.UNAUTHORIZED, "The backend session is invalid or expired.");
		} catch (InvalidFirebaseTokenException exception) {
			return error(HttpStatus.UNAUTHORIZED, "The Firebase ID token is invalid or expired.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the profile read. Confirm the current database rules are published.");
		} catch (ProfileNotFoundException exception) {
			return error(HttpStatus.NOT_FOUND, "The profile was not found. Sign in again to create it.");
		} catch (AccountBannedException exception) {
			return error(HttpStatus.FORBIDDEN, accountBannedMessage(exception));
		} catch (InvalidProfileRoleException exception) {
			logger.error("Firebase profile has an unsupported role");
			return error(HttpStatus.BAD_GATEWAY, "The account profile contains an unsupported role.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while checking the auth session: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@GetMapping("/dashboard")
	public ResponseEntity<?> getDashboard(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		String idToken = getIdToken(authorization);
		if (idToken == null) {
			logger.debug("Rejected dashboard request without a Firebase ID token");
			return error(HttpStatus.UNAUTHORIZED, "A Firebase ID token is required.");
		}

		try {
			BackendJwtService.SessionClaims session = backendJwtService.verify(sessionToken);
			FirebaseAccount account = firebaseRestService.verifyIdToken(idToken);
			if (!account.emailVerified()) {
				logger.warn("Rejected dashboard request for an unverified Firebase account");
				return error(HttpStatus.FORBIDDEN, "Verify your email before opening the dashboard.");
			}
			if (!hasValidDatabaseClaims(account)) {
				logDatabaseClaimMismatch(account);
				return error(
						HttpStatus.UNAUTHORIZED,
						"Firebase verified the account, but the ID token claims are stale or belong to another project. Sign out, then sign in again.");
			}
			if (!session.uid().equals(account.uid())) {
				logger.warn("Rejected dashboard request because Firebase and backend sessions do not match");
				return error(HttpStatus.UNAUTHORIZED, "The sign-in session is invalid. Sign in again.");
			}
			DashboardData dashboard = firebaseRestService.getDashboard(account, idToken);
			logger.debug("Loaded dashboard for authenticated Firebase user");
			return ResponseEntity.ok(dashboard);
		} catch (BackendJwtService.InvalidSessionTokenException exception) {
			logger.warn("Rejected dashboard request with an invalid or expired backend session");
			return error(HttpStatus.UNAUTHORIZED, "The backend session is invalid or expired. Sign in again.");
		} catch (InvalidFirebaseTokenException exception) {
			logger.warn("Rejected dashboard request with an invalid Firebase ID token");
			return error(HttpStatus.UNAUTHORIZED, "The Firebase ID token is invalid or expired.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(
					HttpStatus.FORBIDDEN,
					"Realtime Database rejected the " + exception.operation()
							+ " (HTTP " + exception.statusCode()
							+ "). Confirm the current database.rules.json is published under Realtime Database > Rules.");
		} catch (ProfileNotFoundException exception) {
			logger.warn("Dashboard profile was not found");
			return error(HttpStatus.NOT_FOUND, "The profile was not found. Sign in again to create it.");
		} catch (AccountBannedException exception) {
			return error(HttpStatus.FORBIDDEN, accountBannedMessage(exception));
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while loading the dashboard: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@GetMapping("/servers")
	public ResponseEntity<?> getGameServers(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			List<GameServer> servers = firebaseRestService.getGameServers(authenticated.idToken());
			return ResponseEntity.ok(servers);
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(
					HttpStatus.FORBIDDEN,
					"Realtime Database rejected the " + exception.operation()
							+ " (HTTP " + exception.statusCode()
							+ "). Confirm the current database.rules.json is published under Realtime Database > Rules.");
		} catch (InvalidServerDataException exception) {
			logger.error("The Firebase /servers data does not match the expected server record fields");
			return error(
					HttpStatus.BAD_GATEWAY,
					"The Firebase /servers records contain missing or invalid fields, including maxUsers.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while loading the game server list: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@GetMapping("/characters")
	public ResponseEntity<?> getCharacters(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			List<GameCharacter> characters = firebaseRestService.getCharacters(
					authenticated.idToken(), authenticated.session().uid());
			return ResponseEntity.ok(characters);
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the character list read. Confirm the current database rules are published.");
		} catch (InvalidCharacterDataException exception) {
			logger.error("A saved character record does not match the expected fields");
			return error(HttpStatus.BAD_GATEWAY, "A saved character in Firebase has missing or invalid fields.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while loading characters: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@PostMapping("/characters")
	public ResponseEntity<?> createCharacter(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken,
			@RequestBody(required = false) CreateCharacterRequest request) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			if (!isValidCharacterRequest(request)) {
				return error(
						HttpStatus.BAD_REQUEST,
						"Choose a 3-24 character name and valid character appearance options.");
			}
			boolean serverExists = firebaseRestService.getGameServers(authenticated.idToken()).stream()
					.anyMatch(server -> server.id().equals(request.serverId()));
			if (!serverExists) {
				return error(HttpStatus.NOT_FOUND, "The selected server is no longer available.");
			}
			GameCharacter character = firebaseRestService.createCharacter(
					authenticated.idToken(),
					authenticated.session().uid(),
					request.name().trim(),
					request.serverId(),
					request.classType(),
					request.lineage(),
					request.bodyType(),
					request.hairStyle(),
					request.hairColor(),
					request.faceStyle());
			return ResponseEntity.status(HttpStatus.CREATED).body(character);
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (DuplicateCharacterNameException exception) {
			return error(HttpStatus.CONFLICT, "A character with this name already exists in this server.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied character creation. Confirm the current database rules are published.");
		} catch (InvalidServerDataException exception) {
			logger.error("The Firebase /servers data does not match the expected server record fields");
			return error(HttpStatus.BAD_GATEWAY, "The server list in Firebase contains invalid records.");
		} catch (InvalidCharacterDataException exception) {
			logger.error("Firebase did not return a valid character record key");
			return error(HttpStatus.BAD_GATEWAY, "Firebase did not return a valid character record.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while creating a character: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@DeleteMapping("/characters/{characterId}")
	public ResponseEntity<?> deleteCharacter(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken,
			@PathVariable String characterId) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			if (characterId == null || !characterId.matches("[A-Za-z0-9_-]{1,128}")) {
				return error(HttpStatus.BAD_REQUEST, "The character ID is invalid.");
			}
			firebaseRestService.deleteCharacter(
					authenticated.idToken(),
					authenticated.session().uid(),
					characterId);
			return ResponseEntity.noContent().build();
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (CharacterNotFoundException exception) {
			return error(HttpStatus.NOT_FOUND, "The character was not found in your account.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied character deletion. Confirm the current database rules are published.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while deleting a character: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@GetMapping("/users")
	public ResponseEntity<?> getManagedUsers(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			requireGameMaster(authenticated);
			List<ManagedUser> users = firebaseRestService.getManagedUsers(authenticated.idToken());
			return ResponseEntity.ok(users);
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the user list read. Confirm the current database rules are published.");
		} catch (InvalidManagedUserDataException exception) {
			logger.error("Firebase user profiles do not match the expected profile fields");
			return error(HttpStatus.BAD_GATEWAY, "A user profile in Firebase has missing or invalid fields.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while loading user profiles: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@GetMapping("/gamemaster/activity")
	public ResponseEntity<?> getGameMasterActivity(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			requireGameMaster(authenticated);
			List<GameMasterActivity> activity = firebaseRestService.getGameMasterActivity(
					authenticated.idToken(), authenticated.session().uid());
			return ResponseEntity.ok(activity);
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the Game Master activity read. Confirm the current database rules are published.");
		} catch (InvalidGameMasterActivityDataException exception) {
			logger.error("Game Master activity records do not match the expected fields");
			return error(HttpStatus.BAD_GATEWAY, "A Game Master activity record in Firebase has missing or invalid fields.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while loading Game Master activity: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@GetMapping("/gamemaster/characters")
	public ResponseEntity<?> getGameMasterCharacters(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			requireGameMaster(authenticated);
			List<GameCharacter> characters = firebaseRestService.getAllCharacters(authenticated.idToken());
			return ResponseEntity.ok(characters);
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the player list read. Confirm the current database rules are published.");
		} catch (InvalidCharacterDataException exception) {
			logger.error("A saved character record does not match the expected fields");
			return error(HttpStatus.BAD_GATEWAY, "A saved character in Firebase has missing or invalid fields.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while loading created players: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@PostMapping("/servers")
	public ResponseEntity<?> createGameServer(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken,
			@RequestBody(required = false) CreateServerRequest request) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			requireGameMaster(authenticated);
			if (!isValidServerRequest(request)) {
				return error(
						HttpStatus.BAD_REQUEST,
						"Provide a server name, valid status, recommended flag, and maxUsers from 1 to 100000.");
			}
			String name = request.name().trim();
			String status = request.status().trim().toLowerCase(Locale.ROOT);
			GameServer server = firebaseRestService.addGameServer(
					authenticated.idToken(), name, status, request.recommended(), request.maxUsers());
			firebaseRestService.recordGameMasterActivity(
					authenticated.idToken(),
					authenticated.session().uid(),
					"server_created",
					server.name(),
					"Created server " + server.id() + " with capacity setting " + server.maxUsers() + ".");
			return ResponseEntity.status(HttpStatus.CREATED).body(server);
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (GameMasterActivityWriteException exception) {
			logger.error("A game server was created but its Game Master activity could not be saved", exception);
			return error(HttpStatus.BAD_GATEWAY, "The server was created, but its Game Master activity could not be saved. Check Firebase database rules.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied server creation. Confirm the GM role and current database rules.");
		} catch (InvalidServerDataException exception) {
			logger.error("Firebase returned an invalid result after server creation");
			return error(HttpStatus.BAD_GATEWAY, "Firebase did not return a valid server record.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while creating a game server: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@PatchMapping("/servers/{serverId}/capacity")
	public ResponseEntity<?> updateServerCapacity(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken,
			@PathVariable String serverId,
			@RequestBody(required = false) UpdateCapacityRequest request) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			requireGameMaster(authenticated);
			if (!isValidServerId(serverId) || request == null || !isValidCapacity(request.maxUsers())) {
				return error(HttpStatus.BAD_REQUEST, "Provide a valid server ID and maxUsers from 1 to 100000.");
			}
			firebaseRestService.updateServerCapacity(authenticated.idToken(), serverId, request.maxUsers());
			firebaseRestService.recordGameMasterActivity(
					authenticated.idToken(),
					authenticated.session().uid(),
					"server_capacity_updated",
					serverId,
					"Set the capacity setting to " + request.maxUsers() + " for server " + serverId + ".");
			return ResponseEntity.noContent().build();
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (GameMasterActivityWriteException exception) {
			logger.error("A server capacity was updated but its Game Master activity could not be saved", exception);
			return error(HttpStatus.BAD_GATEWAY, "The capacity setting was updated, but its Game Master activity could not be saved. Check Firebase database rules.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the capacity update. Confirm the GM role and current database rules.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while updating server capacity: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@PatchMapping("/servers/{serverId}/status")
	public ResponseEntity<?> updateServerStatus(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken,
			@PathVariable String serverId,
			@RequestBody(required = false) UpdateServerStatusRequest request) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			requireGameMaster(authenticated);
			if (!isValidServerId(serverId) || request == null
					|| request.status() == null
					|| !SERVER_AVAILABILITY_STATUSES.contains(request.status().trim().toLowerCase(Locale.ROOT))) {
				return error(HttpStatus.BAD_REQUEST, "Provide a valid server ID and choose online or offline.");
			}
			String status = request.status().trim().toLowerCase(Locale.ROOT);
			firebaseRestService.updateServerStatus(authenticated.idToken(), serverId, status);
			firebaseRestService.recordGameMasterActivity(
					authenticated.idToken(),
					authenticated.session().uid(),
					"server_status_updated",
					serverId,
					"Set server " + serverId + " status to " + status + ".");
			return ResponseEntity.noContent().build();
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (GameMasterActivityWriteException exception) {
			logger.error("A server status was updated but its Game Master activity could not be saved", exception);
			return error(HttpStatus.BAD_GATEWAY, "The server status was updated, but its Game Master activity could not be saved. Check Firebase database rules.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the server status update. Confirm the GM role and current database rules.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while updating server status: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@PostMapping("/users/{uid}/ban")
	public ResponseEntity<?> banUser(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken,
			@PathVariable String uid,
			@RequestBody(required = false) BanRequest request) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			requireGameMaster(authenticated);
			if (!isValidUserId(uid) || uid.equals(authenticated.session().uid())) {
				return error(HttpStatus.BAD_REQUEST, "Choose another valid user account to ban.");
			}
			if (request == null || request.durationDays() == null
					|| request.durationDays() < 1 || request.durationDays() > MAX_BAN_DAYS) {
				return error(HttpStatus.BAD_REQUEST, "Ban duration must be from 1 to 365 days.");
			}
			ManagedUser target = firebaseRestService.getManagedUser(authenticated.idToken(), uid);
			if (!"user".equals(target.role())) {
				return error(HttpStatus.FORBIDDEN, "Game-master accounts cannot be banned here.");
			}
			long banUntil = Instant.now().plusSeconds(request.durationDays() * 86_400L).toEpochMilli();
			firebaseRestService.banUser(authenticated.idToken(), uid, banUntil);
			firebaseRestService.recordGameMasterActivity(
					authenticated.idToken(),
					authenticated.session().uid(),
					"user_banned",
					target.name(),
					"Banned account " + uid + " for " + request.durationDays() + " days.");
			return ResponseEntity.ok(Map.of("uid", uid, "banUntil", banUntil));
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (GameMasterActivityWriteException exception) {
			logger.error("A user was banned but the Game Master activity could not be saved", exception);
			return error(HttpStatus.BAD_GATEWAY, "The ban was applied, but its Game Master activity could not be saved. Check Firebase database rules.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the ban update. Confirm the GM role and current database rules.");
		} catch (ProfileNotFoundException exception) {
			return error(HttpStatus.NOT_FOUND, "The user profile was not found.");
		} catch (InvalidManagedUserDataException exception) {
			logger.error("Firebase user profile does not match the expected profile fields");
			return error(HttpStatus.BAD_GATEWAY, "The selected Firebase user profile has invalid fields.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while banning a user: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@PostMapping("/users/{uid}/unban")
	public ResponseEntity<?> unbanUser(
			@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken,
			@PathVariable String uid) {
		try {
			AuthenticatedSession authenticated = authenticateSession(authorization, sessionToken);
			requireGameMaster(authenticated);
			if (!isValidUserId(uid) || uid.equals(authenticated.session().uid())) {
				return error(HttpStatus.BAD_REQUEST, "Choose another valid user account to unban.");
			}
			ManagedUser target = firebaseRestService.getManagedUser(authenticated.idToken(), uid);
			if (!"user".equals(target.role())) {
				return error(HttpStatus.FORBIDDEN, "Game-master accounts cannot be unbanned here.");
			}
			firebaseRestService.unbanUser(authenticated.idToken(), uid);
			firebaseRestService.recordGameMasterActivity(
					authenticated.idToken(),
					authenticated.session().uid(),
					"user_unbanned",
					target.name(),
					"Cleared the ban for account " + uid + ".");
			return ResponseEntity.noContent().build();
		} catch (RequestAuthenticationException exception) {
			return error(exception.status(), exception.getMessage());
		} catch (GameMasterActivityWriteException exception) {
			logger.error("A user was unbanned but the Game Master activity could not be saved", exception);
			return error(HttpStatus.BAD_GATEWAY, "The ban was cleared, but its Game Master activity could not be saved. Check Firebase database rules.");
		} catch (DatabasePermissionException exception) {
			logger.warn(
					"Realtime Database denied operation={} with HTTP status={}",
					exception.operation(),
					exception.statusCode());
			return error(HttpStatus.FORBIDDEN, "Realtime Database denied the unban update. Confirm the GM role and current database rules.");
		} catch (ProfileNotFoundException exception) {
			return error(HttpStatus.NOT_FOUND, "The user profile was not found.");
		} catch (InvalidManagedUserDataException exception) {
			logger.error("Firebase user profile does not match the expected profile fields");
			return error(HttpStatus.BAD_GATEWAY, "The selected Firebase user profile has invalid fields.");
		} catch (FirebaseUnavailableException exception) {
			logger.error("Firebase was unavailable while unbanning a user: {}", exception.getMessage());
			return error(HttpStatus.BAD_GATEWAY, exception.getMessage());
		}
	}

	@PostMapping("/logout")
	public ResponseEntity<Void> logout(
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		try {
			BackendJwtService.SessionClaims session = backendJwtService.verify(sessionToken);
			backendJwtService.revokeSession(session.uid());
		} catch (BackendJwtService.InvalidSessionTokenException ignored) {
			// Clearing the browser cookie is still sufficient for an already invalid session.
		}
		return ResponseEntity.noContent()
				.header(HttpHeaders.SET_COOKIE, authCookie("", Duration.ZERO).toString())
				.header(HttpHeaders.SET_COOKIE, legacyAuthCookie().toString())
				.build();
	}

	private ResponseCookie authCookie(String value, Duration maxAge) {
		return ResponseCookie.from(BackendJwtService.COOKIE_NAME, value)
				.httpOnly(true)
				.secure(secureAuthCookie)
				.sameSite("Lax")
				.path("/")
				.maxAge(maxAge)
				.build();
	}

	private ResponseCookie legacyAuthCookie() {
		return ResponseCookie.from(BackendJwtService.COOKIE_NAME, "")
				.httpOnly(true)
				.secure(secureAuthCookie)
				.sameSite("Lax")
				.path("/api")
				.maxAge(Duration.ZERO)
				.build();
	}

	private String getIdToken(String authorization) {
		if (authorization == null || !authorization.startsWith("Bearer ")) {
			return null;
		}
		String token = authorization.substring("Bearer ".length()).trim();
		return token.isEmpty() ? null : token;
	}

	private AuthenticatedSession authenticateSession(String authorization, String sessionToken) {
		String idToken = getIdToken(authorization);
		if (idToken == null) {
			throw new RequestAuthenticationException(HttpStatus.UNAUTHORIZED, "A Firebase ID token is required.");
		}

		BackendJwtService.SessionClaims session;
		try {
			session = backendJwtService.verify(sessionToken);
		} catch (BackendJwtService.InvalidSessionTokenException exception) {
			throw new RequestAuthenticationException(HttpStatus.UNAUTHORIZED, "The backend session is invalid or expired.");
		}

		FirebaseAccount account;
		try {
			account = firebaseRestService.verifyIdToken(idToken);
		} catch (InvalidFirebaseTokenException exception) {
			throw new RequestAuthenticationException(HttpStatus.UNAUTHORIZED, "The Firebase ID token is invalid or expired.");
		}
		if (!account.emailVerified()) {
			throw new RequestAuthenticationException(HttpStatus.FORBIDDEN, "Verify your email before accessing this resource.");
		}
		if (!hasValidDatabaseClaims(account)) {
			logDatabaseClaimMismatch(account);
			throw new RequestAuthenticationException(
					HttpStatus.UNAUTHORIZED,
					"Firebase verified the account, but the ID token claims are stale or belong to another project. Sign out, then sign in again.");
		}
		if (!session.uid().equals(account.uid())) {
			throw new RequestAuthenticationException(HttpStatus.UNAUTHORIZED, "The sign-in session is invalid. Sign in again.");
		}
		try {
			firebaseRestService.ensureNotBanned(account.uid(), idToken);
		} catch (AccountBannedException exception) {
			throw new RequestAuthenticationException(HttpStatus.FORBIDDEN, accountBannedMessage(exception));
		}
		return new AuthenticatedSession(session, idToken);
	}

	private void requireGameMaster(AuthenticatedSession authenticated) {
		if (!"gamemaster".equals(authenticated.session().role())) {
			throw new RequestAuthenticationException(HttpStatus.FORBIDDEN, "Game-master access is required.");
		}
	}

	private boolean isValidServerRequest(CreateServerRequest request) {
		return request != null
				&& request.name() != null
				&& !request.name().isBlank()
				&& request.name().trim().length() <= 80
				&& request.status() != null
				&& SERVER_STATUSES.contains(request.status().trim().toLowerCase(Locale.ROOT))
				&& isValidCapacity(request.maxUsers());
	}

	private boolean isValidCharacterRequest(CreateCharacterRequest request) {
		return request != null
				&& request.name() != null
				&& request.name().trim().matches("[A-Za-z0-9][A-Za-z0-9 _-]{2,23}")
				&& isValidServerId(request.serverId())
				&& request.classType() != null && CHARACTER_CLASSES.contains(request.classType())
				&& request.lineage() != null && CHARACTER_LINEAGES.contains(request.lineage())
				&& request.bodyType() != null && CHARACTER_BODY_TYPES.contains(request.bodyType())
				&& request.hairStyle() != null && CHARACTER_HAIR_STYLES.contains(request.hairStyle())
				&& request.hairColor() != null && CHARACTER_HAIR_COLORS.contains(request.hairColor())
				&& request.faceStyle() != null && CHARACTER_FACE_STYLES.contains(request.faceStyle());
	}

	private boolean isValidCapacity(Integer maxUsers) {
		return maxUsers != null && maxUsers >= 1 && maxUsers <= MAX_SERVER_USERS;
	}

	private boolean isValidServerId(String serverId) {
		return serverId != null && serverId.matches("[A-Za-z0-9_-]{1,128}");
	}

	private boolean isValidUserId(String uid) {
		return uid != null && uid.matches("[A-Za-z0-9_-]{1,128}");
	}

	private String accountBannedMessage(AccountBannedException exception) {
		return "This account is banned until " + Instant.ofEpochMilli(exception.banUntil()) + ".";
	}

	private boolean hasValidDatabaseClaims(FirebaseAccount account) {
		return account.tokenEmailVerified() && account.tokenUidMatches() && account.tokenAudienceMatches();
	}

	private void logDatabaseClaimMismatch(FirebaseAccount account) {
		logger.warn(
				"Firebase ID token database claims mismatch: emailVerified={}, uidMatches={}, projectAudienceMatches={}",
				account.tokenEmailVerified(),
				account.tokenUidMatches(),
				account.tokenAudienceMatches());
	}

	private ResponseEntity<Map<String, String>> error(HttpStatus status, String message) {
		return ResponseEntity.status(status).body(Map.of("message", message));
	}

	public record CreateServerRequest(String name, String status, boolean recommended, Integer maxUsers) {}

	public record UpdateCapacityRequest(Integer maxUsers) {}

	public record UpdateServerStatusRequest(String status) {}

	public record BanRequest(Integer durationDays) {}

	public record CreateCharacterRequest(
			String name,
			String serverId,
			String classType,
			String lineage,
			String bodyType,
			String hairStyle,
			String hairColor,
			String faceStyle) {}

	private record AuthenticatedSession(BackendJwtService.SessionClaims session, String idToken) {}

	private static class RequestAuthenticationException extends RuntimeException {
		private final HttpStatus status;

		private RequestAuthenticationException(HttpStatus status, String message) {
			super(message);
			this.status = status;
		}

		private HttpStatus status() {
			return status;
		}
	}
}
