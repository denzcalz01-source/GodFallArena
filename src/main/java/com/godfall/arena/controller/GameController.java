package com.godfall.arena.controller;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;

import com.godfall.arena.service.BackendJwtService;

@Controller
public class GameController {

	private static final Logger logger = LoggerFactory.getLogger(GameController.class);

	private final BackendJwtService backendJwtService;
	private final Resource gamePage;
	private final Resource characterCreationPage;
	private final Resource characterSelectionPage;

	public GameController(
			BackendJwtService backendJwtService,
			@Value("classpath:/templates/game.html") Resource gamePage,
			@Value("classpath:/templates/character-creation.html") Resource characterCreationPage,
			@Value("classpath:/templates/characters.html") Resource characterSelectionPage) {
		this.backendJwtService = backendJwtService;
		this.gamePage = gamePage;
		this.characterCreationPage = characterCreationPage;
		this.characterSelectionPage = characterSelectionPage;
	}

	@GetMapping("/game")
	public ResponseEntity<byte[]> gamePortal(
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		return protectedPage(sessionToken, gamePage, "game server list");
	}

	@GetMapping("/character-creation")
	public ResponseEntity<byte[]> characterCreation(
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		return protectedPage(sessionToken, characterCreationPage, "character creation");
	}

	@GetMapping("/characters")
	public ResponseEntity<byte[]> characterSelection(
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		return protectedPage(sessionToken, characterSelectionPage, "character selection");
	}

	private ResponseEntity<byte[]> protectedPage(String sessionToken, Resource page, String pageName) {
		try {
			backendJwtService.verify(sessionToken);
		} catch (BackendJwtService.InvalidSessionTokenException exception) {
			return ResponseEntity.status(HttpStatus.SEE_OTHER)
					.location(URI.create("/?reason=session-ended"))
					.cacheControl(CacheControl.noStore())
					.build();
		}

		try (InputStream input = page.getInputStream()) {
			return ResponseEntity.ok()
					.cacheControl(CacheControl.noStore())
					.contentType(MediaType.TEXT_HTML)
					.body(input.readAllBytes());
		} catch (IOException exception) {
			logger.error("Could not load the protected {} page", pageName, exception);
			return ResponseEntity.internalServerError().build();
		}
	}
}
