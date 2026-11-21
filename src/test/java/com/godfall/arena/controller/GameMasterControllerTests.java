package com.godfall.arena.controller;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import jakarta.servlet.http.Cookie;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import tools.jackson.databind.ObjectMapper;

import com.godfall.arena.service.BackendJwtService;

class GameMasterControllerTests {

	private BackendJwtService backendJwtService;
	private MockMvc mockMvc;

	@BeforeEach
	void setUp() {
		backendJwtService = new BackendJwtService("test-signing-key-that-is-at-least-32-bytes", new ObjectMapper());
		mockMvc = MockMvcBuilders.standaloneSetup(
				new GameMasterController(backendJwtService, new ClassPathResource("templates/gamemaster.html")))
				.build();
	}

	@Test
	void redirectsUnauthenticatedVisitorsToLogin() throws Exception {
		mockMvc.perform(get("/gamemaster"))
				.andExpect(status().isSeeOther())
				.andExpect(header().string("Location", "/?reason=session-ended"));
	}

	@Test
	void redirectsRegularUsersAwayFromGameMasterDashboard() throws Exception {
		String token = backendJwtService.issueUserToken("firebase-user-123");

		mockMvc.perform(get("/gamemaster").cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isSeeOther())
				.andExpect(header().string("Location", "/dashboard.html"));
	}

	@Test
	void servesDashboardOnlyForGameMasterSession() throws Exception {
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		mockMvc.perform(get("/gamemaster").cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
				.andExpect(content().string(containsString("Game master")))
				.andExpect(content().string(containsString("drawer-toggle")))
				.andExpect(content().string(containsString("Enter the world")));
	}

	@Test
	void servesSeparateProtectedGameMasterPages() throws Exception {
		String token = backendJwtService.issueUserToken("firebase-user-123", "gamemaster");

		mockMvc.perform(get("/gamemaster/players").cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isOk())
				.andExpect(content().string(containsString("data-gm-page=\"players\"")));
	}

	@Test
	void redirectsRegularUsersAwayFromSeparateGameMasterPages() throws Exception {
		String token = backendJwtService.issueUserToken("firebase-user-123");

		mockMvc.perform(get("/gamemaster/servers").cookie(new Cookie(BackendJwtService.COOKIE_NAME, token)))
				.andExpect(status().isSeeOther())
				.andExpect(header().string("Location", "/dashboard.html"));
	}
}
