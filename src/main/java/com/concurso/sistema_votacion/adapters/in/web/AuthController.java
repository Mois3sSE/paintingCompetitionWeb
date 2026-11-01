package com.concurso.sistema_votacion.adapters.in.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class AuthController {

	@Value("${spring.datasource.url:jdbc:sqlite:db/votacion.db}")
	private String dbUrl;

	@PostMapping("/login")
	public ResponseEntity<?> login(@RequestBody Map<String, String> credenciales) {
		String usuario = credenciales.get("usuario");
		String password = credenciales.get("password");

		if (usuario == null || password == null) {
			return ResponseEntity.badRequest().body(Map.of("mensaje", "Faltan datos de usuario o contraseña"));
		}

		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
			String passwordHash = HexFormat.of().formatHex(hashBytes);

			try (Connection conn = DriverManager.getConnection(dbUrl);
					PreparedStatement ps = conn.prepareStatement(
							"SELECT id, nombre_usuario, rol FROM USUARIOS WHERE nombre_usuario = ? AND password_hash = ?")) {

				ps.setString(1, usuario.trim().toUpperCase());
				ps.setString(2, passwordHash);

				try (ResultSet rs = ps.executeQuery()) {
					if (rs.next()) {
						return ResponseEntity.ok(Map.of(
								"id", rs.getInt("id"),
								"nombre_usuario", rs.getString("nombre_usuario"),
								"rol", rs.getString("rol")
						));
					} else {
						return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
								.body(Map.of("mensaje", "Usuario o contraseña incorrectos"));
					}
				}
			}
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
		}
	}

	@PostMapping("/registro")
	public ResponseEntity<?> registrar(@RequestBody Map<String, String> datos) {
		String usuario = datos.get("usuario");
		String password = datos.get("password");

		if (usuario == null || usuario.trim().isEmpty() || password == null || password.isEmpty()) {
			return ResponseEntity.badRequest().body(Map.of("mensaje", "Faltan datos de usuario o contraseña"));
		}

		String usuarioMayusculas = usuario.trim().toUpperCase();
		String rolFijo = "PINTOR";

		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			byte[] hashBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
			String passwordHash = HexFormat.of().formatHex(hashBytes);

			try (Connection conn = DriverManager.getConnection(dbUrl);
					PreparedStatement ps = conn.prepareStatement(
							"INSERT INTO USUARIOS (nombre_usuario, rol, password_hash, fecha_creacion) VALUES (?, ?, ?, datetime('now', 'localtime'))")) {

				ps.setString(1, usuarioMayusculas);
				ps.setString(2, rolFijo);
				ps.setString(3, passwordHash);
				ps.executeUpdate();

				return ResponseEntity.status(HttpStatus.CREATED).body(Map.of(
						"mensaje", "Cuenta creada exitosamente",
						"nombre_usuario", usuarioMayusculas,
						"rol", rolFijo
				));
			}
		} catch (SQLException e) {
			if (e.getMessage() != null && e.getMessage().contains("UNIQUE")) {
				return ResponseEntity.status(HttpStatus.CONFLICT)
						.body(Map.of("mensaje", "El nombre de usuario ya está registrado"));
			}
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("mensaje", "Error en la base de datos: " + e.getMessage()));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
		}
	}
}

