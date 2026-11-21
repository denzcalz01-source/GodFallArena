package com.godfall.arena.service;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;

import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

@Service
public class FirebaseRestService {

	private static final String IDENTITY_TOOLKIT_URL =
			"https://identitytoolkit.googleapis.com/v1/accounts:lookup";
	private static final Map<String, String> SERVER_TIMESTAMP = Map.of(".sv", "timestamp");
	private static final Set<String> CHARACTER_CLASSES = Set.of("vanguard", "striker", "arcanist", "warden");
	private static final Set<String> CHARACTER_LINEAGES = Set.of("aetherborn", "stoneborn", "wildkin");
	private static final Set<String> CHARACTER_BODY_TYPES = Set.of("masculine", "feminine");
	private static final Set<String> CHARACTER_HAIR_STYLES = Set.of("crown", "spire", "nomad", "aegis");
	private static final Set<String> CHARACTER_HAIR_COLORS = Set.of("silver", "gold", "ember", "violet");
	private static final Set<String> CHARACTER_FACE_STYLES = Set.of("calm", "focused", "battle-ready");
	private static final TypeReference<Map<String, Object>> TOKEN_CLAIMS_TYPE = new TypeReference<>() {};

	private final RestClient restClient = RestClient.create();
	private final String apiKey;
	private final String databaseUrl;
	private final String projectId;
	private final ObjectMapper objectMapper;

	public FirebaseRestService(
			@Value("${firebase.api-key}") String apiKey,
			@Value("${firebase.database-url}") String databaseUrl,
			@Value("${firebase.project-id}") String projectId,
			ObjectMapper objectMapper) {
		this.apiKey = apiKey;
		this.databaseUrl = databaseUrl;
		this.projectId = projectId;
		this.objectMapper = objectMapper;
	}

	public FirebaseAccount verifyIdToken(String idToken) {
		URI uri = UriComponentsBuilder.fromUriString(IDENTITY_TOOLKIT_URL)
				.queryParam("key", apiKey)
				.build()
				.encode()
				.toUri();

		try {
			LookupResponse response = restClient.post()
					.uri(uri)
					.contentType(MediaType.APPLICATION_JSON)
					.body(Map.of("idToken", idToken))
					.retrieve()
					.body(LookupResponse.class);

			if (response == null || response.users() == null || response.users().isEmpty()) {
				throw new InvalidFirebaseTokenException();
			}

			FirebaseUser user = response.users().get(0);
			if (user.localId() == null || user.email() == null || user.email().isBlank()) {
				throw new InvalidFirebaseTokenException();
			}
			Map<String, Object> claims = decodeIdTokenClaims(idToken);
			String subject = claims.get("sub") instanceof String value ? value : "";
			String tokenUserId = claims.get("user_id") instanceof String value ? value : "";
			String audience = claims.get("aud") instanceof String value ? value : "";
			return new FirebaseAccount(
					user.localId(),
					user.email(),
					Boolean.TRUE.equals(user.emailVerified()),
					user.displayName(),
					Boolean.TRUE.equals(claims.get("email_verified")),
					user.localId().equals(subject) && user.localId().equals(tokenUserId),
					projectId.equals(audience));
		} catch (RestClientResponseException exception) {
			if (exception.getStatusCode().value() == 400 || exception.getStatusCode().value() == 401) {
				throw new InvalidFirebaseTokenException();
			}
			throw new FirebaseUnavailableException("Firebase Authentication could not verify the token.");
		} catch (RestClientException exception) {
			throw new FirebaseUnavailableException("Firebase Authentication could not be reached.");
		}
	}

	public UserProfile saveProfileAndLogLogin(FirebaseAccount account, String idToken) {
		ensureNotBanned(account.uid(), idToken);
		StoredProfile existing = readProfile(account.uid(), idToken);
		boolean newProfile = existing == null;
		String name = account.displayName() != null && !account.displayName().isBlank()
				? account.displayName().trim()
				: existing != null && existing.name() != null && !existing.name().isBlank()
						? existing.name()
						: account.email().substring(0, account.email().indexOf('@'));
		Object createdAt = existing != null && existing.createdAt() != null
				? existing.createdAt()
				: SERVER_TIMESTAMP;
		String role = profileRole(existing);

		Map<String, Object> profile = Map.of(
				"uid", account.uid(),
				"name", name,
				"email", account.email(),
				"emailVerified", true,
				"role", role,
				"createdAt", createdAt,
				"updatedAt", SERVER_TIMESTAMP);
		putJson(databaseUri(idToken, "users", account.uid()), profile);

		if (newProfile) {
			appendLog(account, idToken, "registered");
		}
		appendLog(account, idToken, "login");
		return new UserProfile(
				account.uid(), name, account.email(), true, role, existing == null ? null : existing.createdAt());
	}

	public UserProfile getUserProfile(String uid, String idToken) {
		ensureNotBanned(uid, idToken);
		StoredProfile profile = readProfile(uid, idToken);
		if (profile == null) {
			throw new ProfileNotFoundException();
		}
		return userProfile(profile);
	}

	public DashboardData getDashboard(FirebaseAccount account, String idToken) {
		ensureNotBanned(account.uid(), idToken);
		StoredProfile profile = readProfile(account.uid(), idToken);
		if (profile == null) {
			throw new ProfileNotFoundException();
		}

		Map<String, DatabaseLog> logs = getLogs(idToken, account.uid());
		List<ActivityRecord> activity = logs == null
				? new ArrayList<>()
				: logs.values().stream()
						.map(log -> new ActivityRecord(log.event(), log.createdAt()))
						.sorted(Comparator.comparing(
								ActivityRecord::createdAt,
								Comparator.nullsLast(Comparator.reverseOrder())))
						.limit(6)
						.toList();

		return new DashboardData(userProfile(profile), activity);
	}

	public List<GameServer> getGameServers(String idToken) {
		Map<String, Map<String, Object>> storedServers = databaseCall("server list read", () -> restClient.get()
				.uri(databaseUri(idToken, "servers"))
				.retrieve()
				.body(new ParameterizedTypeReference<Map<String, Map<String, Object>>>() {}));
		if (storedServers == null) {
			return List.of();
		}

		return storedServers.entrySet().stream()
				.map(entry -> toGameServer(entry.getKey(), entry.getValue()))
				.sorted(Comparator.comparing(GameServer::recommended).reversed()
						.thenComparing(GameServer::name, String.CASE_INSENSITIVE_ORDER))
				.toList();
	}

	public GameServer addGameServer(String idToken, String name, String status, boolean recommended, int maxUsers) {
		Map<String, Object> server = Map.of(
				"name", name,
				"status", status,
				"recommended", recommended,
				"maxUsers", maxUsers);
		ServerKeyResponse response = databaseCall("server create", () -> restClient.post()
				.uri(databaseUri(idToken, "servers"))
				.contentType(MediaType.APPLICATION_JSON)
				.body(server)
				.retrieve()
				.body(ServerKeyResponse.class));
		if (response == null || response.name() == null || response.name().isBlank()) {
			throw new InvalidServerDataException();
		}
		return new GameServer(response.name(), name, status, recommended, maxUsers);
	}

	public void updateServerCapacity(String idToken, String serverId, int maxUsers) {
		Map<String, Object> capacity = Map.of("maxUsers", maxUsers);
		databaseCall("server capacity update", () -> restClient.patch()
				.uri(databaseUri(idToken, "servers", serverId))
				.contentType(MediaType.APPLICATION_JSON)
				.body(capacity)
				.retrieve()
				.toBodilessEntity());
	}

	public void updateServerStatus(String idToken, String serverId, String status) {
		Map<String, String> serverStatus = Map.of("status", status);
		databaseCall("server status update", () -> restClient.patch()
				.uri(databaseUri(idToken, "servers", serverId))
				.contentType(MediaType.APPLICATION_JSON)
				.body(serverStatus)
				.retrieve()
				.toBodilessEntity());
	}

	public void banUser(String idToken, String uid, long banUntil) {
		Map<String, Object> ban = Map.of("banUntil", banUntil);
		databaseCall("user ban update", () -> restClient.patch()
				.uri(databaseUri(idToken, "userAccess", uid))
				.contentType(MediaType.APPLICATION_JSON)
				.body(ban)
				.retrieve()
				.toBodilessEntity());
	}

	public void unbanUser(String idToken, String uid) {
		banUser(idToken, uid, 0);
	}

	public void recordGameMasterActivity(String idToken, String uid, String event, String target, String details) {
		Map<String, Object> activity = Map.of(
				"event", event,
				"target", target,
				"details", details,
				"createdAt", SERVER_TIMESTAMP);
		try {
			databaseCall("game-master activity write", () -> restClient.post()
					.uri(databaseUri(idToken, "gmActivity", uid))
					.contentType(MediaType.APPLICATION_JSON)
					.body(activity)
					.retrieve()
					.toBodilessEntity());
		} catch (DatabasePermissionException | FirebaseUnavailableException exception) {
			throw new GameMasterActivityWriteException(exception);
		}
	}

	public List<ManagedUser> getManagedUsers(String idToken) {
		Map<String, Map<String, Object>> storedUsers = databaseCall("user list read", () -> restClient.get()
				.uri(databaseUri(idToken, "users"))
				.retrieve()
				.body(new ParameterizedTypeReference<Map<String, Map<String, Object>>>() {}));
		if (storedUsers == null) {
			return List.of();
		}
		Map<String, UserAccessRecord> accessRecords = databaseCall("user access list read", () -> restClient.get()
				.uri(databaseUri(idToken, "userAccess"))
				.retrieve()
				.body(new ParameterizedTypeReference<Map<String, UserAccessRecord>>() {}));

		return storedUsers.entrySet().stream()
				.map(entry -> toManagedUser(
						entry.getKey(),
						entry.getValue(),
						accessRecords == null ? null : accessRecords.get(entry.getKey())))
				.sorted(Comparator.comparing(ManagedUser::name, String.CASE_INSENSITIVE_ORDER))
				.toList();
	}

	public List<GameMasterActivity> getGameMasterActivity(String idToken, String uid) {
		Map<String, DatabaseGameMasterActivity> entries = databaseCall("game-master activity read", () -> restClient.get()
				.uri(databaseUri(idToken, "gmActivity", uid))
				.retrieve()
				.body(new ParameterizedTypeReference<Map<String, DatabaseGameMasterActivity>>() {}));
		if (entries == null) {
			return List.of();
		}
		return entries.entrySet().stream()
				.map(entry -> toGameMasterActivity(entry.getKey(), entry.getValue()))
				.sorted(Comparator.comparing(
						GameMasterActivity::createdAt,
						Comparator.nullsLast(Comparator.reverseOrder())))
				.limit(10)
				.toList();
	}

	public ManagedUser getManagedUser(String idToken, String uid) {
		Map<String, Object> profile = databaseCall("managed user profile read", () -> restClient.get()
				.uri(databaseUri(idToken, "users", uid))
				.retrieve()
				.body(new ParameterizedTypeReference<Map<String, Object>>() {}));
		if (profile == null) {
			throw new ProfileNotFoundException();
		}
		UserAccessRecord access = readUserAccess(uid, idToken);
		return toManagedUser(uid, profile, access);
	}

	public GameCharacter createCharacter(
			String idToken,
			String uid,
			String name,
			String serverId,
			String classType,
			String lineage,
			String bodyType,
			String hairStyle,
			String hairColor,
			String faceStyle) {
		String characterId = UUID.randomUUID().toString();
		reserveCharacterName(idToken, uid, characterId, name, serverId, false);
		Map<String, Object> character = Map.of(
				"uid", uid,
				"name", name,
				"serverId", serverId,
				"classType", classType,
				"lineage", lineage,
				"bodyType", bodyType,
				"hairStyle", hairStyle,
				"hairColor", hairColor,
				"faceStyle", faceStyle,
				"createdAt", SERVER_TIMESTAMP);
		try {
			databaseCall("character create", () -> restClient.put()
					.uri(databaseUri(idToken, "characters", uid, characterId))
					.contentType(MediaType.APPLICATION_JSON)
					.body(character)
					.retrieve()
					.toBodilessEntity());
		} catch (DatabasePermissionException | FirebaseUnavailableException exception) {
			try {
				deleteCharacterNameReservation(idToken, uid, characterId, serverId, name);
			} catch (DatabasePermissionException | FirebaseUnavailableException cleanupException) {
				exception.addSuppressed(cleanupException);
			}
			throw exception;
		}
		return new GameCharacter(
				characterId, uid, name, serverId, classType, lineage, bodyType, hairStyle, hairColor, faceStyle, null);
	}

	public List<GameCharacter> getCharacters(String idToken, String uid) {
		Map<String, DatabaseGameCharacter> characters = databaseCall("character list read", () -> restClient.get()
				.uri(databaseUri(idToken, "characters", uid))
				.retrieve()
				.body(new ParameterizedTypeReference<Map<String, DatabaseGameCharacter>>() {}));
		if (characters == null) {
			return List.of();
		}
		return characters.entrySet().stream()
				.map(entry -> toGameCharacter(entry.getKey(), uid, entry.getValue()))
				.sorted(Comparator.comparing(
						GameCharacter::createdAt,
						Comparator.nullsLast(Comparator.reverseOrder())))
				.toList();
	}

	public void deleteCharacter(String idToken, String uid, String characterId) {
		DatabaseGameCharacter character = databaseCall("character read before delete", () -> restClient.get()
				.uri(databaseUri(idToken, "characters", uid, characterId))
				.retrieve()
				.body(DatabaseGameCharacter.class));
		if (character == null) {
			throw new CharacterNotFoundException();
		}
		toGameCharacter(characterId, uid, character);
		databaseCall("character delete", () -> restClient.delete()
				.uri(databaseUri(idToken, "characters", uid, characterId))
				.retrieve()
				.toBodilessEntity());
		deleteCharacterNameReservation(
				idToken,
				uid,
				characterId,
				character.serverId(),
				character.name());
	}

	public List<GameCharacter> getAllCharacters(String idToken) {
		Map<String, Map<String, DatabaseGameCharacter>> charactersByUser =
				databaseCall("all character list read", () -> restClient.get()
						.uri(databaseUri(idToken, "characters"))
						.retrieve()
						.body(new ParameterizedTypeReference<Map<String, Map<String, DatabaseGameCharacter>>>() {}));
		if (charactersByUser == null) {
			return List.of();
		}
		List<GameCharacter> characters = new ArrayList<>();
		charactersByUser.forEach((uid, userCharacters) -> {
			if (userCharacters != null) {
				userCharacters.forEach((id, character) -> characters.add(toGameCharacter(id, uid, character)));
			}
		});
		List<GameCharacter> orderedCharacters = characters.stream()
				.sorted(Comparator.comparing(GameCharacter::serverId, String.CASE_INSENSITIVE_ORDER)
						.thenComparing(GameCharacter::name, String.CASE_INSENSITIVE_ORDER))
				.toList();
		orderedCharacters.forEach(character -> reserveCharacterName(
				idToken,
				character.uid(),
				character.id(),
				character.name(),
				character.serverId(),
				true));
		return orderedCharacters;
	}

	private void reserveCharacterName(
			String idToken,
			String uid,
			String characterId,
			String name,
			String serverId,
			boolean ignoreExisting) {
		URI nameUri = databaseUri(idToken, "characterNames", serverId, characterNameKey(name));
		ResponseEntity<String> existing = databaseCall("character name check", () -> restClient.get()
				.uri(nameUri)
				.header("X-Firebase-ETag", "true")
				.retrieve()
				.toEntity(String.class));
		String existingBody = existing.getBody();
		if (existingBody != null && !existingBody.isBlank() && !"null".equals(existingBody.trim())) {
			if (ignoreExisting) {
				return;
			}
			throw new DuplicateCharacterNameException();
		}
		String etag = existing.getHeaders().getFirst(HttpHeaders.ETAG);
		if (etag == null || etag.isBlank()) {
			throw new FirebaseUnavailableException("Realtime Database did not return a character-name concurrency token.");
		}
		Map<String, String> reservation = Map.of(
				"uid", uid,
				"characterId", characterId,
				"name", name,
				"serverId", serverId);
		try {
			databaseCall("character name reservation", () -> restClient.put()
					.uri(nameUri)
					.header(HttpHeaders.IF_MATCH, etag)
					.contentType(MediaType.APPLICATION_JSON)
					.body(reservation)
					.retrieve()
					.toBodilessEntity());
		} catch (FirebaseUnavailableException exception) {
			if (Integer.valueOf(412).equals(exception.statusCode())) {
				if (ignoreExisting) {
					return;
				}
				throw new DuplicateCharacterNameException();
			}
			throw exception;
		}
	}

	private void deleteCharacterNameReservation(
			String idToken,
			String uid,
			String characterId,
			String serverId,
			String name) {
		URI nameUri = databaseUri(idToken, "characterNames", serverId, characterNameKey(name));
		DatabaseCharacterName reservation = databaseCall("character name reservation read", () -> restClient.get()
				.uri(nameUri)
				.retrieve()
				.body(DatabaseCharacterName.class));
		if (reservation == null
				|| !uid.equals(reservation.uid())
				|| !characterId.equals(reservation.characterId())) {
			return;
		}
		databaseCall("character name reservation delete", () -> restClient.delete()
				.uri(nameUri)
				.retrieve()
				.toBodilessEntity());
	}

	private String characterNameKey(String name) {
		try {
			byte[] digest = MessageDigest.getInstance("SHA-256")
					.digest(name.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
			return HexFormat.of().formatHex(digest);
		} catch (NoSuchAlgorithmException exception) {
			throw new IllegalStateException("SHA-256 is required to index character names.", exception);
		}
	}

	private GameServer toGameServer(String id, Map<String, Object> data) {
		Object maxUsers = data == null ? null : data.get("maxUsers");
		if (id == null || id.isBlank() || data == null
				|| !(data.get("name") instanceof String name) || name.isBlank()
				|| !(data.get("status") instanceof String status) || status.isBlank()
				|| (data.get("recommended") != null && !(data.get("recommended") instanceof Boolean))
				|| (maxUsers != null && !(maxUsers instanceof Number))) {
			throw new InvalidServerDataException();
		}
		Integer capacity = maxUsers instanceof Number number ? number.intValue() : null;
		if (capacity != null
				&& (capacity < 1 || capacity > 100_000 || ((Number) maxUsers).doubleValue() != capacity)) {
			throw new InvalidServerDataException();
		}
		return new GameServer(
				id,
				name.trim(),
				status.trim(),
				Boolean.TRUE.equals(data.get("recommended")),
				capacity);
	}

	private ManagedUser toManagedUser(String uid, Map<String, Object> data, UserAccessRecord access) {
		Long banUntil = access == null ? null : access.banUntil();
		if (uid == null || uid.isBlank() || data == null
				|| !uid.equals(data.get("uid"))
				|| !(data.get("name") instanceof String name) || name.isBlank()
				|| !(data.get("email") instanceof String email) || email.isBlank()
				|| !(data.get("role") instanceof String role)
				|| !("user".equals(role) || "gamemaster".equals(role))
				|| (data.get("emailVerified") != null && !(data.get("emailVerified") instanceof Boolean))
				|| (data.get("createdAt") != null && !(data.get("createdAt") instanceof Number))
				|| (banUntil != null && banUntil < 0)) {
			throw new InvalidManagedUserDataException();
		}
		Object createdAt = data.get("createdAt");
		return new ManagedUser(
				uid,
				name.trim(),
				email.trim(),
				Boolean.TRUE.equals(data.get("emailVerified")),
				role,
				createdAt instanceof Number timestamp ? timestamp.longValue() : null,
				banUntil);
	}

	private GameMasterActivity toGameMasterActivity(String id, DatabaseGameMasterActivity activity) {
		if (id == null || id.isBlank() || activity == null
				|| !isValidGameMasterEvent(activity.event())
				|| activity.target() == null || activity.target().isBlank()
				|| activity.details() == null || activity.details().isBlank()
				|| activity.createdAt() == null || activity.createdAt() < 0) {
			throw new InvalidGameMasterActivityDataException();
		}
		return new GameMasterActivity(
				id,
				activity.event(),
				activity.target().trim(),
				activity.details().trim(),
				activity.createdAt());
	}

	private GameCharacter toGameCharacter(String id, String uid, DatabaseGameCharacter character) {
		if (id == null || id.isBlank() || uid == null || uid.isBlank() || character == null
				|| (character.uid() != null && !uid.equals(character.uid()))
				|| character.name() == null
				|| !character.name().matches("[A-Za-z0-9][A-Za-z0-9 _-]{2,23}")
				|| character.serverId() == null
				|| !character.serverId().matches("[A-Za-z0-9_-]{1,128}")
				|| character.classType() == null || !CHARACTER_CLASSES.contains(character.classType())
				|| character.lineage() == null || !CHARACTER_LINEAGES.contains(character.lineage())
				|| character.bodyType() == null || !CHARACTER_BODY_TYPES.contains(character.bodyType())
				|| character.hairStyle() == null || !CHARACTER_HAIR_STYLES.contains(character.hairStyle())
				|| character.hairColor() == null || !CHARACTER_HAIR_COLORS.contains(character.hairColor())
				|| character.faceStyle() == null || !CHARACTER_FACE_STYLES.contains(character.faceStyle())
				|| character.createdAt() == null || character.createdAt() < 0) {
			throw new InvalidCharacterDataException();
		}
		return new GameCharacter(
				id,
				uid,
				character.name().trim(),
				character.serverId(),
				character.classType(),
				character.lineage(),
				character.bodyType(),
				character.hairStyle(),
				character.hairColor(),
				character.faceStyle(),
				character.createdAt());
	}

	private boolean isValidGameMasterEvent(String event) {
		return "user_banned".equals(event)
				|| "user_unbanned".equals(event)
				|| "server_created".equals(event)
				|| "server_capacity_updated".equals(event)
				|| "server_status_updated".equals(event);
	}

	public void ensureNotBanned(String uid, String idToken) {
		UserAccessRecord access = readUserAccess(uid, idToken);
		if (access != null && access.banUntil() != null && access.banUntil() > System.currentTimeMillis()) {
			throw new AccountBannedException(access.banUntil());
		}
	}

	private UserAccessRecord readUserAccess(String uid, String idToken) {
		return databaseCall("user access read", () -> restClient.get()
				.uri(databaseUri(idToken, "userAccess", uid))
				.retrieve()
				.body(UserAccessRecord.class));
	}

	private UserProfile userProfile(StoredProfile profile) {
		return new UserProfile(
				profile.uid(),
				profile.name(),
				profile.email(),
				Boolean.TRUE.equals(profile.emailVerified()),
				profileRole(profile),
				profile.createdAt());
	}

	private String profileRole(StoredProfile profile) {
		String role = profile == null || profile.role() == null || profile.role().isBlank()
				? "user"
				: profile.role();
		if (!("user".equals(role) || "gamemaster".equals(role))) {
			throw new InvalidProfileRoleException();
		}
		return role;
	}

	private StoredProfile readProfile(String uid, String idToken) {
		return databaseCall("profile read", () -> restClient.get()
				.uri(databaseUri(idToken, "users", uid))
				.retrieve()
				.body(StoredProfile.class));
	}

	private Map<String, DatabaseLog> getLogs(String idToken, String uid) {
		URI uri = databaseUriBuilder(idToken, "authLogs", uid)
				.queryParam("orderBy", "\"$key\"")
				.queryParam("limitToLast", 6)
				.build()
				.encode()
				.toUri();
		return databaseCall("activity log read", () -> restClient.get()
				.uri(uri)
				.retrieve()
				.body(new ParameterizedTypeReference<Map<String, DatabaseLog>>() {}));
	}

	private void putJson(URI uri, Object body) {
		databaseCall("profile write", () -> restClient.put()
				.uri(uri)
				.contentType(MediaType.APPLICATION_JSON)
				.body(body)
				.retrieve()
				.toBodilessEntity());
	}

	private void appendLog(FirebaseAccount account, String idToken, String event) {
		Map<String, Object> log = Map.of(
				"uid", account.uid(),
				"email", account.email(),
				"event", event,
				"createdAt", SERVER_TIMESTAMP);
		databaseCall(event + " activity write", () -> restClient.post()
				.uri(databaseUri(idToken, "authLogs", account.uid()))
				.contentType(MediaType.APPLICATION_JSON)
				.body(log)
				.retrieve()
				.toBodilessEntity());
	}

	private URI databaseUri(String idToken, String... pathSegments) {
		return databaseUriBuilder(idToken, pathSegments)
				.build()
				.encode()
				.toUri();
	}

	private Map<String, Object> decodeIdTokenClaims(String idToken) {
		String[] parts = idToken.split("\\.", -1);
		if (parts.length != 3) {
			throw new InvalidFirebaseTokenException();
		}
		try {
			return objectMapper.readValue(Base64.getUrlDecoder().decode(parts[1]), TOKEN_CLAIMS_TYPE);
		} catch (IllegalArgumentException | JacksonException exception) {
			throw new InvalidFirebaseTokenException();
		}
	}

	private UriComponentsBuilder databaseUriBuilder(String idToken, String... pathSegments) {
		return UriComponentsBuilder.fromUriString(databaseUrl)
				.pathSegment(pathSegments)
				.path(".json")
				.queryParam("auth", idToken);
	}

	private <T> T databaseCall(String operation, Supplier<T> request) {
		try {
			return request.get();
		} catch (RestClientResponseException exception) {
			if (exception.getStatusCode().value() == 401 || exception.getStatusCode().value() == 403) {
				throw new DatabasePermissionException(operation, exception.getStatusCode().value());
			}
			throw new FirebaseUnavailableException(operation, exception.getStatusCode().value());
		} catch (RestClientException exception) {
			throw new FirebaseUnavailableException(operation, null);
		}
	}

	public record FirebaseAccount(
			String uid,
			String email,
			boolean emailVerified,
			String displayName,
			boolean tokenEmailVerified,
			boolean tokenUidMatches,
			boolean tokenAudienceMatches) {}

	public record UserProfile(String uid, String name, String email, boolean emailVerified, String role, Long createdAt) {}

	public record ActivityRecord(String event, Long createdAt) {}

	public record DashboardData(UserProfile user, List<ActivityRecord> activity) {}

	public record GameServer(String id, String name, String status, boolean recommended, Integer maxUsers) {}

	public record ManagedUser(
			String uid,
			String name,
			String email,
			boolean emailVerified,
			String role,
			Long createdAt,
			Long banUntil) {}

	public record GameMasterActivity(String id, String event, String target, String details, Long createdAt) {}

	public record GameCharacter(
			String id,
			String uid,
			String name,
			String serverId,
			String classType,
			String lineage,
			String bodyType,
			String hairStyle,
			String hairColor,
			String faceStyle,
			Long createdAt) {}

	private record LookupResponse(List<FirebaseUser> users) {}

	private record FirebaseUser(String localId, String email, Boolean emailVerified, String displayName) {}

	private record ServerKeyResponse(String name) {}

	private record UserAccessRecord(Long banUntil) {}

	private record DatabaseGameMasterActivity(String event, String target, String details, Long createdAt) {}

	private record DatabaseCharacterName(String uid, String characterId, String name, String serverId) {}

	private record DatabaseGameCharacter(
			String uid,
			String name,
			String serverId,
			String classType,
			String lineage,
			String bodyType,
			String hairStyle,
			String hairColor,
			String faceStyle,
			Long createdAt) {}

	private record StoredProfile(
			String uid, String name, String email, Boolean emailVerified, String role, Long createdAt, Long updatedAt) {}

	private record DatabaseLog(String uid, String email, String event, Long createdAt) {}

	public static class InvalidFirebaseTokenException extends RuntimeException {}

	public static class DatabasePermissionException extends RuntimeException {
		private final String operation;
		private final int statusCode;

		public DatabasePermissionException(String operation, int statusCode) {
			this.operation = operation;
			this.statusCode = statusCode;
		}

		public String operation() {
			return operation;
		}

		public int statusCode() {
			return statusCode;
		}
	}

	public static class FirebaseUnavailableException extends RuntimeException {
		private final String operation;
		private final Integer statusCode;

		public FirebaseUnavailableException(String message) {
			super(message);
			operation = null;
			statusCode = null;
		}

		public FirebaseUnavailableException(String operation, Integer statusCode) {
			super(statusCode == null
					? "Realtime Database request failed during " + operation + "."
					: "Realtime Database returned HTTP " + statusCode + " during " + operation + ".");
			this.operation = operation;
			this.statusCode = statusCode;
		}

		public String operation() {
			return operation;
		}

		public Integer statusCode() {
			return statusCode;
		}
	}

	public static class ProfileNotFoundException extends RuntimeException {}

	public static class InvalidServerDataException extends RuntimeException {}

	public static class InvalidManagedUserDataException extends RuntimeException {}

	public static class InvalidProfileRoleException extends RuntimeException {}

	public static class AccountBannedException extends RuntimeException {
		private final long banUntil;

		public AccountBannedException(long banUntil) {
			this.banUntil = banUntil;
		}

		public long banUntil() {
			return banUntil;
		}
	}

	public static class InvalidGameMasterActivityDataException extends RuntimeException {}

	public static class InvalidCharacterDataException extends RuntimeException {}

	public static class DuplicateCharacterNameException extends RuntimeException {}

	public static class CharacterNotFoundException extends RuntimeException {}

	public static class GameMasterActivityWriteException extends RuntimeException {
		public GameMasterActivityWriteException(RuntimeException cause) {
			super("A Game Master action completed, but its activity entry could not be written.", cause);
		}
	}
}
