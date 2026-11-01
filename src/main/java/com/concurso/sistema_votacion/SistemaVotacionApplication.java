package com.concurso.sistema_votacion;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.Statement;
import java.time.LocalDateTime;

@SpringBootApplication
@RestController
public class SistemaVotacionApplication {

	@Value("${spring.datasource.url:jdbc:sqlite:db/votacion.db}")
	private String dbUrl;

	public static void main(String[] args) {
		SpringApplication.run(SistemaVotacionApplication.class, args);
	}

	@GetMapping(value = "/", produces = "text/html;charset=UTF-8")
	public String simularBaseDeDatos() {
		StringBuilder html = new StringBuilder();
		html.append("<!DOCTYPE html><html lang='es'><head><meta charset='UTF-8'>");
		html.append("<title>Simulación de Base de Datos - Sistema de Votación</title>");
		html.append("<style>");
		html.append("body { font-family: Arial, sans-serif; margin: 25px; background: #f4f6f9; color: #333; }");
		html.append(
				"h1 { color: #1a5276; } h2 { color: #2e86c1; margin-top: 25px; border-bottom: 2px solid #2e86c1; padding-bottom: 5px; }");
		html.append(
				".status { background: #d4efdf; color: #196f3d; padding: 12px; border-radius: 6px; font-weight: bold; margin-bottom: 20px; }");
		html.append(
				"table { border-collapse: collapse; width: 100%; background: #fff; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 15px; }");
		html.append("th, td { border: 1px solid #dcdcdc; padding: 8px 12px; text-align: left; font-size: 14px; }");
		html.append("th { background: #2e86c1; color: #fff; } tr:nth-child(even) { background: #f9f9f9; }");
		html.append("</style></head><body>");
		html.append("<h1>Simulación de Llenado y Conexión a Base de Datos (SQLite)</h1>");

		try (Connection conn = DriverManager.getConnection(dbUrl)) {
			try (Statement pragmaStmt = conn.createStatement()) {
				pragmaStmt.execute("PRAGMA foreign_keys = ON;");
			}

			// Verificamos si ya existen datos de prueba para no duplicar en cada recarga, o
			// insertamos si está vacía
			int totalUsuarios = 0;
			try (Statement st = conn.createStatement();
					ResultSet rs = st.executeQuery("SELECT COUNT(*) FROM USUARIOS")) {
				if (rs.next()) {
					totalUsuarios = rs.getInt(1);
				}
			}

			String ahora = LocalDateTime.now().toString();

			if (totalUsuarios == 0) {
				// 1. Insertar USUARIOS (Pintor, Juez, Presidente)
				int pintorId = insertarUsuario(conn, "pintor_demo", "PINTOR", "hash_sha256_pintor_123", ahora);
				int juezId = insertarUsuario(conn, "juez_demo", "JUEZ", "hash_sha256_juez_456", ahora);
				int presidenteId = insertarUsuario(conn, "presidente_demo", "PRESIDENTE", "hash_sha256_pres_789",
						ahora);

				// 2. Insertar LLAVES_EC (para el pintor y juez)
				try (PreparedStatement ps = conn.prepareStatement(
						"INSERT INTO LLAVES_EC (usuario_id, llave_publica) VALUES (?, ?)")) {
					ps.setInt(1, pintorId);
					ps.setString(2, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE_LLAVE_EC_PINTOR_SIMULADA");
					ps.executeUpdate();

					ps.setInt(1, juezId);
					ps.setString(2, "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE_LLAVE_EC_JUEZ_SIMULADA");
					ps.executeUpdate();
				}

				// 3. Insertar LLAVES_RSA (para el presidente y juez)
				try (PreparedStatement ps = conn.prepareStatement(
						"INSERT INTO LLAVES_RSA (usuario_id, llave_publica) VALUES (?, ?)")) {
					ps.setInt(1, presidenteId);
					ps.setString(2, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A_LLAVE_RSA_PRESIDENTE_SIMULADA");
					ps.executeUpdate();

					ps.setInt(1, juezId);
					ps.setString(2, "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A_LLAVE_RSA_JUEZ_SIMULADA");
					ps.executeUpdate();
				}

				// 4. Insertar OBRAS
				int obraId = 0;
				try (PreparedStatement ps = conn.prepareStatement(
						"INSERT INTO OBRAS (titulo, autor_id, nombre_archivo_original, ruta_imagen_cifrada, firma_ecdsa_pintor, fecha_registro) VALUES (?, ?, ?, ?, ?, ?)",
						Statement.RETURN_GENERATED_KEYS)) {
					ps.setString(1, "La Noche Criptográfica");
					ps.setInt(2, pintorId);
					ps.setString(3, "noche_cripto.png");
					ps.setString(4, "storage/encrypted/noche_cripto.enc");
					ps.setString(5, "MEUCIQD_FIRMA_ECDSA_SIMULADA_PINTOR_001");
					ps.setString(6, ahora);
					ps.executeUpdate();
					try (ResultSet keys = ps.getGeneratedKeys()) {
						if (keys.next())
							obraId = keys.getInt(1);
					}
				}

				// 5. Insertar ACTAS_EVALUACION
				int actaId = 0;
				try (PreparedStatement ps = conn.prepareStatement(
						"INSERT INTO ACTAS_EVALUACION (obra_id, juez_id, estrellas, comentario, fecha_evaluacion) VALUES (?, ?, ?, ?, ?)",
						Statement.RETURN_GENERATED_KEYS)) {
					ps.setInt(1, obraId);
					ps.setInt(2, juezId);
					ps.setInt(3, 5);
					ps.setString(4, "Excelente técnica y composición (Simulación)");
					ps.setString(5, ahora);
					ps.executeUpdate();
					try (ResultSet keys = ps.getGeneratedKeys()) {
						if (keys.next())
							actaId = keys.getInt(1);
					}
				}

				// 6. Insertar ARTEFACTOS_CHAUM
				try (PreparedStatement ps = conn.prepareStatement(
						"INSERT INTO ARTEFACTOS_CHAUM (acta_id, voto_cegado_b64, firma_ciega_presidente_b64, firma_descegada_b64) VALUES (?, ?, ?, ?)")) {
					ps.setInt(1, actaId);
					ps.setString(2, "Vk9UT19DRUdBRE9fU0lNVUxBRE9fQjY0");
					ps.setString(3, "RklSTUFfQ0lFR0FfUFJFU0lERU5URV9CNjQ=");
					ps.setString(4, "RklSTUFfREVTY0VHQURBX1ZBTElEQV9CNjQ=");
					ps.executeUpdate();
				}

				// 7. Insertar RESULTADOS_CONCURSO
				try (PreparedStatement ps = conn.prepareStatement(
						"INSERT INTO RESULTADOS_CONCURSO (obra_id, promedio, lugar_ranking) VALUES (?, ?, ?)")) {
					ps.setInt(1, obraId);
					ps.setDouble(2, 5.0);
					ps.setInt(3, 1);
					ps.executeUpdate();
				}

				html.append("<div class='status'>Conexión exitosa a <code>").append(dbUrl)
						.append("</code>. Se insertaron datos de simulación en las 7 tablas correctamente.</div>");
			} else {
				html.append("<div class='status'>Conexión exitosa a <code>").append(dbUrl)
						.append("</code>. Mostrando los datos almacenados en las 7 tablas.</div>");
			}

			String[] tablas = {
					"USUARIOS",
					"LLAVES_EC",
					"LLAVES_RSA",
					"OBRAS",
					"ACTAS_EVALUACION",
					"ARTEFACTOS_CHAUM",
					"RESULTADOS_CONCURSO"
			};

			for (String tabla : tablas) {
				html.append("<h2>Tabla: ").append(tabla).append("</h2>");
				try (Statement st = conn.createStatement();
						ResultSet rs = st.executeQuery("SELECT * FROM " + tabla)) {
					ResultSetMetaData meta = rs.getMetaData();
					int cols = meta.getColumnCount();

					html.append("<table><thead><tr>");
					for (int i = 1; i <= cols; i++) {
						html.append("<th>").append(meta.getColumnName(i)).append("</th>");
					}
					html.append("</tr></thead><tbody>");

					boolean tieneFilas = false;
					while (rs.next()) {
						tieneFilas = true;
						html.append("<tr>");
						for (int i = 1; i <= cols; i++) {
							Object val = rs.getObject(i);
							html.append("<td>").append(val != null ? val.toString() : "NULL").append("</td>");
						}
						html.append("</tr>");
					}
					if (!tieneFilas) {
						html.append("<tr><td colspan='").append(cols).append("'>Sin registros</td></tr>");
					}
					html.append("</tbody></table>");
				}
			}

		} catch (Exception e) {
			html.append("<div style='background:#fdedec;color:#c0392b;padding:12px;border-radius:6px;'>");
			html.append("<strong>Error al conectar o poblar la base de datos:</strong> ").append(e.getMessage());
			html.append("</div>");
		}

		html.append("</body></html>");
		return html.toString();
	}

	private int insertarUsuario(Connection conn, String username, String rol, String passHash, String fecha) throws Exception {
		try (PreparedStatement ps = conn.prepareStatement(
				"INSERT INTO USUARIOS (nombre_usuario, rol, password_hash, fecha_creacion) VALUES (?, ?, ?, ?)",
				Statement.RETURN_GENERATED_KEYS)) {
			ps.setString(1, username);
			ps.setString(2, rol);
			ps.setString(3, passHash);
			ps.setString(4, fecha);
			ps.executeUpdate();
			try (ResultSet keys = ps.getGeneratedKeys()) {
				if (keys.next()) {
					return keys.getInt(1);
				}
			}
		}
		throw new IllegalStateException("No se pudo obtener el ID del usuario insertado");
	}

}
