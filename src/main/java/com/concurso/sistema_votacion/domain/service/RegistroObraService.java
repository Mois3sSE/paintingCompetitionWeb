package com.concurso.sistema_votacion.domain.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.concurso.sistema_votacion.domain.model.Obra;
import com.concurso.sistema_votacion.domain.model.ResultadoFirmaObra;
import com.concurso.sistema_votacion.domain.model.UsuarioInfo;
import com.concurso.sistema_votacion.ports.in.RegistroObraPintorUseCase;
import com.concurso.sistema_votacion.ports.out.LlavesECRepositoryPort;
import com.concurso.sistema_votacion.ports.out.ObrasRepositoryPort;
import com.concurso.sistema_votacion.ports.out.RegistroECDSAPort;
import com.concurso.sistema_votacion.ports.out.UsuariosRepositoryPort;

/**
 * Servicio de dominio: Firma digital ECDSA de la obra del Pintor.
 *
 * Flujo:
 * 1. Cargar la llave privada EC del pintor desde su almacenamiento local
 *    (claves_usuarios/Pintores/<NombreUsuario>/<NombreUsuario>_priv.pem).
 * 2. Calcular el hash SHA-256 de la obra cifrada.
 * 3. Firmar la obra cifrada con SHA256withECDSA (curva secp256r1).
 * 4. Verificar la firma con la llave pública del pintor guardada en la BD (LLAVES_EC).
 * 5. Guardar la obra cifrada en imagenes/ y registrar la obra con su firma en la tabla OBRAS.
 */
@Service
public class RegistroObraService implements RegistroObraPintorUseCase {

    private static final Path DIR_PINTORES = Paths.get("claves_usuarios", "Pintores");
    private static final Path DIR_IMAGENES = Paths.get("imagenes");
    private static final String ALGORITMO = "SHA256withECDSA (Curva secp256r1)";
    private static final DateTimeFormatter FORMATO_SELLO = DateTimeFormatter.ofPattern("yyyyMMddHHmmss");

    private final RegistroECDSAPort registroECDSAPort;
    private final LlavesECRepositoryPort llavesECRepositoryPort;
    private final ObrasRepositoryPort obrasRepositoryPort;
    private final UsuariosRepositoryPort usuariosRepositoryPort;

    public RegistroObraService(
            RegistroECDSAPort registroECDSAPort,
            LlavesECRepositoryPort llavesECRepositoryPort,
            ObrasRepositoryPort obrasRepositoryPort,
            UsuariosRepositoryPort usuariosRepositoryPort) {
        this.registroECDSAPort = registroECDSAPort;
        this.llavesECRepositoryPort = llavesECRepositoryPort;
        this.obrasRepositoryPort = obrasRepositoryPort;
        this.usuariosRepositoryPort = usuariosRepositoryPort;
    }

    @Override
    public ResultadoFirmaObra registrarObraFirmada(int pintorId, String titulo,
            String nombreArchivoOriginal, byte[] obraCifrada) throws Exception {

        UsuarioInfo pintor = obtenerPintor(pintorId);

        if (titulo == null || titulo.isBlank()) {
            throw new IllegalArgumentException("El título de la obra es obligatorio.");
        }
        if (obraCifrada == null || obraCifrada.length == 0) {
            throw new IllegalArgumentException("No hay datos de obra para firmar.");
        }

        String nombreNormalizado = pintor.nombreUsuario().trim().replaceAll("\\s+", "_");
        Path rutaLlavePrivada = DIR_PINTORES.resolve(nombreNormalizado).resolve(nombreNormalizado + "_priv.pem");
        if (!Files.exists(rutaLlavePrivada)) {
            throw new IllegalStateException(
                    "No se encontró la llave privada del pintor en: " + rutaLlavePrivada
                            + ". Inicie sesión de nuevo para generarla.");
        }

        // 1. Cargar la llave privada del pintor (queda solo en el almacenamiento local)
        PrivateKey privPintor = registroECDSAPort.cargarLlavePrivada(rutaLlavePrivada);

        // 2. Hash matemático (SHA-256) de la obra cifrada
        byte[] hashObra = MessageDigest.getInstance("SHA-256").digest(obraCifrada);

        // 3. Firma digital ECDSA (SHA256withECDSA calcula el hash internamente)
        byte[] firmaDigital = registroECDSAPort.firmarECDSA(obraCifrada, privPintor);

        // 4. Verificar con la llave pública del pintor registrada en la BD (LLAVES_EC)
        boolean verificada = false;
        Optional<String> llavePublicaB64 = llavesECRepositoryPort.obtenerLlavePublicaPorUsuario(pintorId);
        if (llavePublicaB64.isPresent()) {
            PublicKey pubPintor = registroECDSAPort.llavePublicaDesdeBase64(llavePublicaB64.get());
            verificada = registroECDSAPort.verificarFirmaECDSA(obraCifrada, firmaDigital, pubPintor);
        }
        if (!verificada) {
            throw new IllegalStateException(
                    "La firma no coincide con la llave pública del pintor en la base de datos. "
                            + "La obra no se registró.");
        }

        // 5. Guardar la obra cifrada en imagenes/ con el formato nombreBase_Cifrado_Autor_sello.ext
        String nombreOriginal = Paths.get(nombreArchivoOriginal).getFileName().toString();
        int puntoIdx = nombreOriginal.lastIndexOf('.');
        String nombreBase = (puntoIdx > 0) ? nombreOriginal.substring(0, puntoIdx) : nombreOriginal;
        String extension = (puntoIdx > 0) ? nombreOriginal.substring(puntoIdx) : "";
        String sello = LocalDateTime.now().format(FORMATO_SELLO);
        Path rutaObra = DIR_IMAGENES.resolve(
                nombreBase + "_Cifrado_" + nombreNormalizado + "_" + sello + extension);

        Files.createDirectories(DIR_IMAGENES);
        Files.write(rutaObra, obraCifrada);

        // 6. Inyectar la obra y su firma (Base64) en la tabla OBRAS
        String firmaBase64 = Base64.getEncoder().encodeToString(firmaDigital);
        String rutaGuardada = rutaObra.toString().replace('\\', '/');
        int obraId = obrasRepositoryPort.insertarObra(
                titulo.trim(), pintorId, nombreOriginal, rutaGuardada, firmaBase64);

        return new ResultadoFirmaObra(
                obraId,
                titulo.trim(),
                pintor.nombreUsuario(),
                nombreOriginal,
                rutaGuardada,
                obraCifrada.length,
                ALGORITMO,
                HexFormat.of().withUpperCase().formatHex(hashObra),
                firmaDigital.length,
                HexFormat.of().withUpperCase().formatHex(firmaDigital),
                firmaBase64,
                verificada);
    }

    @Override
    public List<Obra> listarObrasDelPintor(int pintorId) throws Exception {
        obtenerPintor(pintorId);
        return obrasRepositoryPort.listarObrasPorAutor(pintorId);
    }

    private UsuarioInfo obtenerPintor(int pintorId) throws Exception {
        UsuarioInfo usuario = usuariosRepositoryPort.buscarPorId(pintorId)
                .orElseThrow(() -> new IllegalArgumentException("El usuario no existe."));
        if (!"PINTOR".equalsIgnoreCase(usuario.rol())) {
            throw new SecurityException("Solo un PINTOR puede registrar obras.");
        }
        return usuario;
    }
}
