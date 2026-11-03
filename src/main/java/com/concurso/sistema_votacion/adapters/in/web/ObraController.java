package com.concurso.sistema_votacion.adapters.in.web;

import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.concurso.sistema_votacion.ports.in.RegistroObraPintorUseCase;
import com.concurso.sistema_votacion.ports.in.VerificacionFirmaObraUseCase;

/**
 * Adaptador de entrada web para el registro de obras con firma ECDSA (Pintor)
 * y la verificación de autenticidad de obras (Juez).
 * Integrante 2 - Registro, Identidad y No Repudio.
 */
@RestController
@RequestMapping("/api/obras")
public class ObraController {

	private static final Set<String> EXTENSIONES_PERMITIDAS = Set.of(".png", ".jpg", ".jpeg", ".bmp", ".gif");

	private final RegistroObraPintorUseCase registroObraPintorUseCase;
	private final VerificacionFirmaObraUseCase verificacionFirmaObraUseCase;

	public ObraController(
			RegistroObraPintorUseCase registroObraPintorUseCase,
			VerificacionFirmaObraUseCase verificacionFirmaObraUseCase) {
		this.registroObraPintorUseCase = registroObraPintorUseCase;
		this.verificacionFirmaObraUseCase = verificacionFirmaObraUseCase;
	}

	// PINTOR: registrar obra y firmarla con ECDSA
	@PostMapping
	public ResponseEntity<?> registrarObra(
			@RequestParam("usuarioId") int usuarioId,
			@RequestParam("titulo") String titulo,
			@RequestParam("archivo") MultipartFile archivo) {

		if (archivo == null || archivo.isEmpty()) {
			return ResponseEntity.badRequest().body(Map.of("mensaje", "Debe seleccionar una imagen."));
		}

		String nombreOriginal = archivo.getOriginalFilename() != null ? archivo.getOriginalFilename() : "obra";
		int puntoIdx = nombreOriginal.lastIndexOf('.');
		String extension = (puntoIdx > 0) ? nombreOriginal.substring(puntoIdx).toLowerCase(Locale.ROOT) : "";
		if (!EXTENSIONES_PERMITIDAS.contains(extension)) {
			return ResponseEntity.badRequest()
					.body(Map.of("mensaje", "Formato no permitido. Use: " + EXTENSIONES_PERMITIDAS));
		}

		try {
			// TODO Integrante 1: aquí se cifra la imagen con AES-256-GCM (llave derivada por ECDH)
			// antes de firmarla. Mientras tanto se firman los bytes recibidos tal cual.
			byte[] obraCifrada = archivo.getBytes();

			return ResponseEntity.status(HttpStatus.CREATED).body(
					registroObraPintorUseCase.registrarObraFirmada(usuarioId, titulo, nombreOriginal, obraCifrada));
		} catch (Exception e) {
			return manejarError(e);
		}
	}

	// PINTOR: consultar mis obras registradas
	@GetMapping("/pintor/{usuarioId}")
	public ResponseEntity<?> listarObrasDelPintor(@PathVariable int usuarioId) {
		try {
			return ResponseEntity.ok(registroObraPintorUseCase.listarObrasDelPintor(usuarioId));
		} catch (Exception e) {
			return manejarError(e);
		}
	}

	// JUEZ: catálogo de obras registradas
	@GetMapping("/juez/{usuarioId}")
	public ResponseEntity<?> listarObrasParaJuez(@PathVariable int usuarioId) {
		try {
			return ResponseEntity.ok(verificacionFirmaObraUseCase.listarObrasParaJuez(usuarioId));
		} catch (Exception e) {
			return manejarError(e);
		}
	}

	// JUEZ: análisis de autenticidad e integridad de la obra (ECDSA)
	@GetMapping("/{obraId}/verificar-firma")
	public ResponseEntity<?> verificarFirma(@PathVariable int obraId, @RequestParam("usuarioId") int usuarioId) {
		try {
			return ResponseEntity.ok(verificacionFirmaObraUseCase.verificarFirmaObra(usuarioId, obraId));
		} catch (Exception e) {
			return manejarError(e);
		}
	}

	private ResponseEntity<?> manejarError(Exception e) {
		if (e instanceof SecurityException) {
			return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("mensaje", e.getMessage()));
		}
		if (e instanceof IllegalArgumentException || e instanceof IllegalStateException) {
			return ResponseEntity.badRequest().body(Map.of("mensaje", e.getMessage()));
		}
		return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
				.body(Map.of("mensaje", "Error en el servidor: " + e.getMessage()));
	}
}
