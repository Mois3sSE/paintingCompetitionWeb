package com.concurso.sistema_votacion.adapters.in.web;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.concurso.sistema_votacion.ports.out.AnonimatoRSAPort;

/**
 * Integrante 3 - Firma a ciegas de Chaum (RSA 3072).
 * 1. Juez: vota y ciega su voto m' = m * r^e mod N (r se queda en su carpeta local).
 * 2. Presidente: firma el voto cegado s' = (m')^d mod N sin ver las estrellas.
 * 3. Juez: desciega s = s' * r^-1 mod N y verifica s^e mod N == m.
 * 4. Resultados: solo cuentan los votos cuya firma se verifica.
 */
@RestController
@RequestMapping("/api/chaum")
public class FirmaCiegaController {

	private static final Path DIR_FACTORES = Paths.get("claves_usuarios", "Jueces", "factores_cegado");

	@Value("${spring.datasource.url:jdbc:sqlite:db/votacion.db}")
	private String dbUrl;

	private final AnonimatoRSAPort anonimatoRSAPort;

	public FirmaCiegaController(AnonimatoRSAPort anonimatoRSAPort) {
		this.anonimatoRSAPort = anonimatoRSAPort;
	}

	// JUEZ: registrar el voto (acta) y cegarlo con la llave pública del presidente
	@PostMapping("/votar")
	public ResponseEntity<?> votar(@RequestBody Map<String, String> datos) {
		try (Connection conn = DriverManager.getConnection(dbUrl)) {
			int juezId = Integer.parseInt(datos.get("usuarioId"));
			int obraId = Integer.parseInt(datos.get("obraId"));
			int estrellas = Integer.parseInt(datos.get("estrellas"));
			if (!tieneRol(conn, juezId, "JUEZ") || estrellas < 1 || estrellas > 3) {
				return ResponseEntity.badRequest().body(Map.of("mensaje", "Solo un JUEZ puede votar, de 1 a 3 estrellas."));
			}
			try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM ACTAS_EVALUACION WHERE obra_id = ? AND juez_id = ?")) {
				ps.setInt(1, obraId);
				ps.setInt(2, juezId);
				if (ps.executeQuery().next()) {
					return ResponseEntity.badRequest().body(Map.of("mensaje", "Ya votaste por esta obra."));
				}
			}

			int actaId;
			try (PreparedStatement ps = conn.prepareStatement(
					"INSERT INTO ACTAS_EVALUACION (obra_id, juez_id, estrellas, comentario, fecha_evaluacion) VALUES (?, ?, ?, ?, datetime('now', 'localtime'))",
					Statement.RETURN_GENERATED_KEYS)) {
				ps.setInt(1, obraId);
				ps.setInt(2, juezId);
				ps.setInt(3, estrellas);
				ps.setString(4, datos.get("comentario"));
				ps.executeUpdate();
				ResultSet keys = ps.getGeneratedKeys();
				keys.next();
				actaId = keys.getInt(1);
			}

			// Cegado: m' = m * r^e mod N
			RSAPublicKey pubPresidente = llavePublicaPresidente(conn);
			BigInteger r = anonimatoRSAPort.generarFactorCegado(pubPresidente);
			byte[] votoCegado = anonimatoRSAPort.cegarMensaje(mensajeVoto(juezId, obraId, estrellas), r, pubPresidente);

			// El factor r se queda solo con el juez (almacenamiento local)
			Files.createDirectories(DIR_FACTORES);
			Files.writeString(DIR_FACTORES.resolve("acta_" + actaId + "_r.txt"), r.toString(16));

			try (PreparedStatement ps = conn.prepareStatement(
					"INSERT INTO ARTEFACTOS_CHAUM (acta_id, voto_cegado_b64, firma_ciega_presidente_b64, firma_descegada_b64) VALUES (?, ?, '', '')")) {
				ps.setInt(1, actaId);
				ps.setString(2, Base64.getEncoder().encodeToString(votoCegado));
				ps.executeUpdate();
			}
			return ResponseEntity.ok(Map.of("mensaje", "Voto cegado y enviado al presidente (acta " + actaId + ")."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
		}
	}

	// JUEZ: sus votos y el estado de la firma ciega
	@GetMapping("/votos-juez/{usuarioId}")
	public ResponseEntity<?> votosJuez(@PathVariable int usuarioId) {
		return listarActas("WHERE a.juez_id = " + usuarioId, true);
	}

	// PRESIDENTE: votos cegados (sin ver las estrellas)
	@GetMapping("/votos-cegados")
	public ResponseEntity<?> votosCegados() {
		return listarActas("", false);
	}

	// PRESIDENTE: firma a ciegas con su llave privada (archivo .pem cargado en la página)
	@PostMapping("/firmar")
	public ResponseEntity<?> firmar(@RequestParam("usuarioId") int usuarioId,
			@RequestParam("actas") List<Integer> actas,
			@RequestParam("llavePrivada") MultipartFile llavePrivada) {
		try (Connection conn = DriverManager.getConnection(dbUrl)) {
			if (!tieneRol(conn, usuarioId, "PRESIDENTE")) {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("mensaje", "Solo el PRESIDENTE puede firmar."));
			}
			String pem = new String(llavePrivada.getBytes(), StandardCharsets.UTF_8).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s+", "");
			RSAPrivateKey privPresidente = (RSAPrivateKey) KeyFactory.getInstance("RSA")
					.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(pem)));

			for (int actaId : actas) {
				byte[] votoCegado = Base64.getDecoder().decode(consultar(conn, "SELECT voto_cegado_b64 FROM ARTEFACTOS_CHAUM WHERE acta_id = ?", actaId));
				// Firma ciega: s' = (m')^d mod N
				byte[] firmaCiega = anonimatoRSAPort.firmarCegadoRSA(votoCegado, privPresidente);
				try (PreparedStatement ps = conn.prepareStatement("UPDATE ARTEFACTOS_CHAUM SET firma_ciega_presidente_b64 = ? WHERE acta_id = ?")) {
					ps.setString(1, Base64.getEncoder().encodeToString(firmaCiega));
					ps.setInt(2, actaId);
					ps.executeUpdate();
				}
			}
			return ResponseEntity.ok(Map.of("mensaje", "Se firmaron a ciegas " + actas.size() + " voto(s)."));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("mensaje", "Error al firmar: " + e.getMessage()));
		}
	}

	// JUEZ: descegar la firma del presidente y verificarla
	@PostMapping("/descegar/{actaId}")
	public ResponseEntity<?> descegar(@PathVariable int actaId, @RequestParam("usuarioId") int usuarioId) {
		try (Connection conn = DriverManager.getConnection(dbUrl)) {
			Map<String, Object> acta = leerActa(conn, actaId);
			if (acta == null || (int) acta.get("juezId") != usuarioId || ((String) acta.get("firmaCiega")).isEmpty()) {
				return ResponseEntity.badRequest().body(Map.of("mensaje", "El voto aún no ha sido firmado por el presidente."));
			}
			RSAPublicKey pubPresidente = llavePublicaPresidente(conn);
			BigInteger r = new BigInteger(Files.readString(DIR_FACTORES.resolve("acta_" + actaId + "_r.txt")).trim(), 16);

			// Descegado: s = s' * r^-1 mod N
			byte[] firma = anonimatoRSAPort.descegarFirmaRSA(Base64.getDecoder().decode((String) acta.get("firmaCiega")), r, pubPresidente);
			boolean valida = anonimatoRSAPort.verificarFirmaRSA((byte[]) acta.get("mensaje"), firma, pubPresidente);

			try (PreparedStatement ps = conn.prepareStatement("UPDATE ARTEFACTOS_CHAUM SET firma_descegada_b64 = ? WHERE acta_id = ?")) {
				ps.setString(1, Base64.getEncoder().encodeToString(firma));
				ps.setInt(2, actaId);
				ps.executeUpdate();
			}
			return ResponseEntity.ok(Map.of("valida", valida, "mensaje", valida
					? "Firma descegada VALIDA: s^e mod N == m"
					: "[ALERTA] Firma descegada INVALIDA"));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("mensaje", "Error al descegar: " + e.getMessage()));
		}
	}

	// Resultados: verifica cada firma descegada y promedia solo los votos válidos
	@GetMapping("/resultados")
	public ResponseEntity<?> resultados() {
		try (Connection conn = DriverManager.getConnection(dbUrl)) {
			RSAPublicKey pubPresidente = llavePublicaPresidente(conn);
			Map<Integer, Map<String, Object>> porObra = new LinkedHashMap<>();
			try (PreparedStatement ps = conn.prepareStatement(
					"SELECT a.id FROM ACTAS_EVALUACION a JOIN ARTEFACTOS_CHAUM c ON c.acta_id = a.id WHERE c.firma_descegada_b64 <> ''");
					ResultSet rs = ps.executeQuery()) {
				while (rs.next()) {
					Map<String, Object> acta = leerActa(conn, rs.getInt("id"));
					boolean valida = anonimatoRSAPort.verificarFirmaRSA((byte[]) acta.get("mensaje"),
							Base64.getDecoder().decode((String) acta.get("firmaDescegada")), pubPresidente);
					Map<String, Object> obra = porObra.computeIfAbsent((int) acta.get("obraId"), k -> new LinkedHashMap<>(Map.of(
							"obraId", k, "titulo", acta.get("titulo"), "suma", 0, "votos", 0, "vulnerado", false)));
					if (valida) {
						obra.put("suma", (int) obra.get("suma") + (int) acta.get("estrellas"));
						obra.put("votos", (int) obra.get("votos") + 1);
					} else {
						obra.put("vulnerado", true);
					}
				}
			}

			List<Map<String, Object>> ranking = new ArrayList<>();
			for (Map<String, Object> obra : porObra.values()) {
				if (!(boolean) obra.get("vulnerado") && (int) obra.get("votos") > 0) {
					obra.put("promedio", (double) (int) obra.get("suma") / (int) obra.get("votos"));
					ranking.add(obra);
				}
			}
			ranking.sort((a, b) -> Double.compare((double) b.get("promedio"), (double) a.get("promedio")));

			try (Statement st = conn.createStatement()) {
				st.executeUpdate("DELETE FROM RESULTADOS_CONCURSO");
			}
			for (int i = 0; i < ranking.size(); i++) {
				ranking.get(i).put("lugar", i + 1);
				try (PreparedStatement ps = conn.prepareStatement("INSERT INTO RESULTADOS_CONCURSO (obra_id, promedio, lugar_ranking) VALUES (?, ?, ?)")) {
					ps.setInt(1, (int) ranking.get(i).get("obraId"));
					ps.setDouble(2, (double) ranking.get(i).get("promedio"));
					ps.setInt(3, i + 1);
					ps.executeUpdate();
				}
			}
			List<Map<String, Object>> vulnerados = porObra.values().stream().filter(o -> (boolean) o.get("vulnerado")).toList();
			return ResponseEntity.ok(Map.of("ranking", ranking, "vulnerados", vulnerados));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
		}
	}

	// m = "JUEZ:<id>|OBRA:<id>|ESTRELLAS:<n>" (lo que el presidente firma sin ver)
	private byte[] mensajeVoto(int juezId, int obraId, int estrellas) {
		return ("JUEZ:" + juezId + "|OBRA:" + obraId + "|ESTRELLAS:" + estrellas).getBytes(StandardCharsets.UTF_8);
	}

	private ResponseEntity<?> listarActas(String filtro, boolean mostrarEstrellas) {
		try (Connection conn = DriverManager.getConnection(dbUrl);
				PreparedStatement ps = conn.prepareStatement(
						"SELECT a.id, o.titulo, u.nombre_usuario, a.estrellas, c.voto_cegado_b64, c.firma_ciega_presidente_b64, c.firma_descegada_b64 " +
						"FROM ACTAS_EVALUACION a JOIN OBRAS o ON o.id = a.obra_id JOIN USUARIOS u ON u.id = a.juez_id " +
						"JOIN ARTEFACTOS_CHAUM c ON c.acta_id = a.id " + filtro + " ORDER BY a.id");
				ResultSet rs = ps.executeQuery()) {
			List<Map<String, Object>> actas = new ArrayList<>();
			while (rs.next()) {
				Map<String, Object> acta = new LinkedHashMap<>();
				acta.put("actaId", rs.getInt("id"));
				acta.put("obra", rs.getString("titulo"));
				acta.put("juez", rs.getString("nombre_usuario"));
				acta.put("estrellas", mostrarEstrellas ? rs.getInt("estrellas") : "oculto");
				acta.put("votoCegado", rs.getString("voto_cegado_b64").substring(0, 40) + "...");
				acta.put("estado", !rs.getString("firma_descegada_b64").isEmpty() ? "DESCEGADO"
						: !rs.getString("firma_ciega_presidente_b64").isEmpty() ? "FIRMADO" : "PENDIENTE DE FIRMA");
				actas.add(acta);
			}
			return ResponseEntity.ok(actas);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
		}
	}

	private Map<String, Object> leerActa(Connection conn, int actaId) throws Exception {
		try (PreparedStatement ps = conn.prepareStatement(
				"SELECT a.obra_id, a.juez_id, a.estrellas, o.titulo, c.firma_ciega_presidente_b64, c.firma_descegada_b64 " +
				"FROM ACTAS_EVALUACION a JOIN OBRAS o ON o.id = a.obra_id JOIN ARTEFACTOS_CHAUM c ON c.acta_id = a.id WHERE a.id = ?")) {
			ps.setInt(1, actaId);
			try (ResultSet rs = ps.executeQuery()) {
				if (!rs.next()) {
					return null;
				}
				Map<String, Object> acta = new LinkedHashMap<>();
				acta.put("obraId", rs.getInt("obra_id"));
				acta.put("juezId", rs.getInt("juez_id"));
				acta.put("estrellas", rs.getInt("estrellas"));
				acta.put("titulo", rs.getString("titulo"));
				acta.put("firmaCiega", rs.getString("firma_ciega_presidente_b64"));
				acta.put("firmaDescegada", rs.getString("firma_descegada_b64"));
				acta.put("mensaje", mensajeVoto(rs.getInt("juez_id"), rs.getInt("obra_id"), rs.getInt("estrellas")));
				return acta;
			}
		}
	}

	private RSAPublicKey llavePublicaPresidente(Connection conn) throws Exception {
		try (Statement st = conn.createStatement();
				ResultSet rs = st.executeQuery(
						"SELECT k.llave_publica FROM LLAVES_RSA k JOIN USUARIOS u ON u.id = k.usuario_id WHERE u.rol = 'PRESIDENTE'")) {
			if (!rs.next()) {
				throw new IllegalStateException("El presidente aún no tiene llave pública RSA (debe iniciar sesión una vez).");
			}
			byte[] llave = Base64.getDecoder().decode(rs.getString(1));
			return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(llave));
		}
	}

	private String consultar(Connection conn, String sql, int id) throws Exception {
		try (PreparedStatement ps = conn.prepareStatement(sql)) {
			ps.setInt(1, id);
			try (ResultSet rs = ps.executeQuery()) {
				if (!rs.next()) {
					throw new IllegalStateException("No se encontró el dato solicitado.");
				}
				return rs.getString(1);
			}
		}
	}

	private boolean tieneRol(Connection conn, int usuarioId, String rol) throws Exception {
		try (PreparedStatement ps = conn.prepareStatement("SELECT rol FROM USUARIOS WHERE id = ?")) {
			ps.setInt(1, usuarioId);
			try (ResultSet rs = ps.executeQuery()) {
				return rs.next() && rol.equalsIgnoreCase(rs.getString("rol"));
			}
		}
	}
}
