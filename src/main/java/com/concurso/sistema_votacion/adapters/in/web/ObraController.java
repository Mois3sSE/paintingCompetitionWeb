package com.concurso.sistema_votacion.adapters.in.web;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.MediaTypeFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.concurso.sistema_votacion.domain.crypto.ModuloConfidencialidadAES;
import com.concurso.sistema_votacion.ports.out.RegistroECDSAPort;

/**
 * Registro, Identidad y No Repudio (ECDSA).
 * El juez consulta las obras y verifica la firma ECDSA del pintor
 * (tabla OBRAS) con la llave pública del pintor (tabla LLAVES_EC).
 */
@RestController
@RequestMapping("/api/obras")
public class ObraController {

	@Value("${spring.datasource.url:jdbc:sqlite:db/votacion.db}")
	private String dbUrl;

	private final RegistroECDSAPort registroECDSAPort;
	private final ModuloConfidencialidadAES moduloConfidencialidadAES;

	public ObraController(RegistroECDSAPort registroECDSAPort, ModuloConfidencialidadAES moduloConfidencialidadAES) {
		this.registroECDSAPort = registroECDSAPort;
		this.moduloConfidencialidadAES = moduloConfidencialidadAES;
	}

	// JUEZ: catálogo de obras registradas
	@GetMapping("/juez/{usuarioId}")
	public ResponseEntity<?> listarObras(@PathVariable int usuarioId) {
		try (Connection conn = DriverManager.getConnection(dbUrl)) {
			if (!esJuez(conn, usuarioId)) {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("mensaje", "Solo un JUEZ puede ver las obras."));
			}
			List<Map<String, Object>> obras = new ArrayList<>();
			try (PreparedStatement ps = conn.prepareStatement(
					"SELECT o.id, o.titulo, u.nombre_usuario, o.nombre_archivo_original, o.fecha_registro " +
					"FROM OBRAS o JOIN USUARIOS u ON u.id = o.autor_id ORDER BY o.id");
					ResultSet rs = ps.executeQuery()) {
				while (rs.next()) {
					obras.add(Map.of(
							"id", rs.getInt("id"),
							"titulo", rs.getString("titulo"),
							"autor", rs.getString("nombre_usuario"),
							"archivo", rs.getString("nombre_archivo_original"),
							"fecha", rs.getString("fecha_registro")));
				}
			}
			return ResponseEntity.ok(obras);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
		}
	}

	// JUEZ: verificar la firma ECDSA de la obra -> VALIDA / INVALIDA
	@GetMapping("/{obraId}/verificar-firma")
	public ResponseEntity<?> verificarFirma(@PathVariable int obraId, @RequestParam("usuarioId") int usuarioId) {
		try (Connection conn = DriverManager.getConnection(dbUrl)) {
			if (!esJuez(conn, usuarioId)) {
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("mensaje", "Solo un JUEZ puede verificar obras."));
			}
			Map<String, String> obra = leerObra(conn, obraId);
			if (obra == null) {
				return ResponseEntity.badRequest().body(Map.of("mensaje", "La obra no existe."));
			}

			if (!Files.exists(Paths.get(obra.get("ruta")))) {
				return ResponseEntity.badRequest().body(Map.of("mensaje", "No se encontró el archivo de la obra: " + obra.get("ruta")));
			}
			byte[] datosObra = Files.readAllBytes(Paths.get(obra.get("ruta")));
			boolean valida = firmaValida(obra, datosObra);

			// Prueba de integridad: si se altera 1 byte, la firma ya no coincide
			byte[] obraAlterada = datosObra.clone();
			obraAlterada[obraAlterada.length - 1] ^= 0x01;
			boolean alteracionDetectada = !firmaValida(obra, obraAlterada);

			Map<String, Object> resultado = new HashMap<>(obra);
			resultado.put("algoritmo", "SHA256withECDSA (Curva secp256r1)");
			resultado.put("hashSha256", HexFormat.of().withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(datosObra)));
			resultado.put("valida", valida);
			resultado.put("resultado", valida ? "VALIDA" : "INVALIDA");
			resultado.put("alteracionDetectada", alteracionDetectada);
			resultado.put("mensaje", valida
					? "La obra es auténtica y no sufrió ninguna modificación."
					: "[ALERTA] La firma no coincide o la obra fue alterada. No se descifrará la imagen.");
			return ResponseEntity.ok(resultado);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
		}
	}

	// JUEZ: ver la imagen. Solo se descifra (Integrante 1) si la firma ECDSA es VALIDA
	@GetMapping("/{obraId}/imagen")
	public ResponseEntity<?> verImagen(@PathVariable int obraId, @RequestParam("usuarioId") int usuarioId) {
		try (Connection conn = DriverManager.getConnection(dbUrl)) {
			Map<String, String> obra = leerObra(conn, obraId);
			if (!esJuez(conn, usuarioId) || obra == null || !Files.exists(Paths.get(obra.get("ruta")))) {
				return ResponseEntity.badRequest().body(Map.of("mensaje", "Obra no disponible."));
			}
			byte[] datosObra = Files.readAllBytes(Paths.get(obra.get("ruta")));
			if (!firmaValida(obra, datosObra)) {
				return ResponseEntity.badRequest().body(Map.of("mensaje", "Firma INVALIDA: no se descifra la imagen."));
			}
			byte[] imagen = moduloConfidencialidadAES.descifrarObra(datosObra, obra.get("llavePublica"));
			return ResponseEntity.ok()
					.contentType(MediaTypeFactory.getMediaType(obra.get("archivo")).orElse(MediaType.APPLICATION_OCTET_STREAM))
					.body(imagen);
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
		}
	}

	// Lee de la BD la obra (OBRAS), su autor y la llave pública del autor (LLAVES_EC)
	private Map<String, String> leerObra(Connection conn, int obraId) throws Exception {
		try (PreparedStatement ps = conn.prepareStatement(
				"SELECT o.titulo, u.nombre_usuario, o.nombre_archivo_original, o.ruta_imagen_cifrada, o.firma_ecdsa_pintor, k.llave_publica " +
				"FROM OBRAS o JOIN USUARIOS u ON u.id = o.autor_id LEFT JOIN LLAVES_EC k ON k.usuario_id = o.autor_id WHERE o.id = ?")) {
			ps.setInt(1, obraId);
			try (ResultSet rs = ps.executeQuery()) {
				if (!rs.next()) {
					return null;
				}
				Map<String, String> obra = new HashMap<>();
				obra.put("titulo", rs.getString("titulo"));
				obra.put("autor", rs.getString("nombre_usuario"));
				obra.put("archivo", rs.getString("nombre_archivo_original"));
				obra.put("ruta", rs.getString("ruta_imagen_cifrada"));
				obra.put("firma", rs.getString("firma_ecdsa_pintor"));
				obra.put("llavePublica", rs.getString("llave_publica"));
				return obra;
			}
		}
	}

	// Verifica la firma (Base64) con la llave pública del pintor (Base64 X.509)
	private boolean firmaValida(Map<String, String> obra, byte[] datosObra) {
		try {
			byte[] firma = Base64.getDecoder().decode(obra.get("firma"));
			byte[] llave = Base64.getDecoder().decode(obra.get("llavePublica"));
			PublicKey pubPintor = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(llave));
			return registroECDSAPort.verificarFirmaECDSA(datosObra, firma, pubPintor);
		} catch (Exception e) {
			return false;
		}
	}

	private boolean esJuez(Connection conn, int usuarioId) throws Exception {
		try (PreparedStatement ps = conn.prepareStatement("SELECT rol FROM USUARIOS WHERE id = ?")) {
			ps.setInt(1, usuarioId);
			try (ResultSet rs = ps.executeQuery()) {
				return rs.next() && "JUEZ".equalsIgnoreCase(rs.getString("rol"));
			}
		}
	}
}
