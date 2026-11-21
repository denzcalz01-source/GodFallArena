package com.godfall.arena.controller;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import com.godfall.arena.service.BackendJwtService;

@Controller
public class GameMasterController {

	private static final Logger logger = LoggerFactory.getLogger(GameMasterController.class);
	private static final Set<String> SECTIONS = Set.of("users", "servers", "players", "activity");

	private final BackendJwtService backendJwtService;
	private final Resource dashboardPage;

	public GameMasterController(
			BackendJwtService backendJwtService,
			@Value("classpath:/templates/gamemaster.html") Resource dashboardPage) {
		this.backendJwtService = backendJwtService;
		this.dashboardPage = dashboardPage;
	}

	@GetMapping({"/gamemaster", "/gamemaster/{section}"})
	public ResponseEntity<byte[]> dashboard(
			@PathVariable(required = false) String section,
			@CookieValue(value = BackendJwtService.COOKIE_NAME, required = false) String sessionToken) {
		if (section != null && !SECTIONS.contains(section)) {
			return redirect("/gamemaster");
		}
		BackendJwtService.SessionClaims session;
		try {
			session = backendJwtService.verify(sessionToken);
		} catch (BackendJwtService.InvalidSessionTokenException exception) {
			return redirect("/?reason=session-ended");
		}

		if (!"gamemaster".equals(session.role())) {
			return redirect("/dashboard.html");
		}

		try (InputStream input = dashboardPage.getInputStream()) {
			return ResponseEntity.ok()
					.cacheControl(CacheControl.noStore())
					.contentType(MediaType.TEXT_HTML)
					.body(input.readAllBytes());
		} catch (IOException exception) {
			logger.error("Could not load the protected game-master dashboard", exception);
			return ResponseEntity.internalServerError().build();
		}
	}

	private ResponseEntity<byte[]> redirect(String location) {
		return ResponseEntity.status(HttpStatus.SEE_OTHER)
				.location(URI.create(location))
				.cacheControl(CacheControl.noStore())
				.build();
	}
}
