package com.concurso.sistema_votacion.domain.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.concurso.sistema_votacion.domain.model.Obra;
import com.concurso.sistema_votacion.domain.model.ResultadoVerificacionFirma;
import com.concurso.sistema_votacion.domain.model.UsuarioInfo;
import com.concurso.sistema_votacion.ports.in.VerificacionFirmaObraUseCase;
import com.concurso.sistema_votacion.ports.out.LlavesECRepositoryPort;
import com.concurso.sistema_votacion.ports.out.ObrasRepositoryPort;
import com.concurso.sistema_votacion.ports.out.RegistroECDSAPort;
import com.concurso.sistema_votacion.ports.out.UsuariosRepositoryPort;

/**
 * Servicio de dominio: Análisis de autenticidad e integridad de la obra.
 *
 * Flujo:
 * 1. Leer de la BD la obra (OBRAS) con su firma ECDSA en Base64.
 * 2. Leer de la BD la llave pública EC del pintor (LLAVES_EC).
 * 3. Leer el archivo de la obra cifrada guardado en imagenes/.
 * 4. Verificar SHA256withECDSA -> VALIDA / INVALIDA.
 * Si es VALIDA, el Juez puede continuar con la recuperación de la llave AES y el
 * descifrado de la imagen (Integrante 1).
 */
@Service
public class VerificacionFirmaObraService implements VerificacionFirmaObraUseCase {

    private static final String ALGORITMO = "SHA256withECDSA (Curva secp256r1)";

    private final RegistroECDSAPort registroECDSAPort;
    private final LlavesECRepositoryPort llavesECRepositoryPort;
    private final ObrasRepositoryPort obrasRepositoryPort;
    private final UsuariosRepositoryPort usuariosRepositoryPort;

    public VerificacionFirmaObraService(
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
    public List<Obra> listarObrasParaJuez(int juezId) throws Exception {
        validarJuez(juezId);
        return obrasRepositoryPort.listarObras();
    }

    @Override
    public ResultadoVerificacionFirma verificarFirmaObra(int juezId, int obraId) throws Exception {
        validarJuez(juezId);

        Obra obra = obrasRepositoryPort.buscarPorId(obraId)
                .orElseThrow(() -> new IllegalArgumentException("La obra con ID " + obraId + " no existe."));

        Optional<String> llavePublicaB64 = llavesECRepositoryPort.obtenerLlavePublicaPorUsuario(obra.autorId());
        if (llavePublicaB64.isEmpty()) {
            return invalida(obra, null, null, "No se encontró la llave pública del pintor en la base de datos.");
        }

        Path rutaObra = Paths.get(obra.rutaImagenCifrada());
        if (!Files.exists(rutaObra)) {
            return invalida(obra, null, llavePublicaB64.get(),
                    "No se encontró el archivo de la obra en: " + rutaObra);
        }

        byte[] datosObra = Files.readAllBytes(rutaObra);
        String hashHex = HexFormat.of().withUpperCase()
                .formatHex(MessageDigest.getInstance("SHA-256").digest(datosObra));

        byte[] firma;
        try {
            firma = Base64.getDecoder().decode(obra.firmaEcdsaPintorB64());
        } catch (IllegalArgumentException e) {
            return invalida(obra, hashHex, llavePublicaB64.get(), "La firma guardada no es Base64 válido.");
        }

        PublicKey pubPintor = registroECDSAPort.llavePublicaDesdeBase64(llavePublicaB64.get());
        boolean esValida = registroECDSAPort.verificarFirmaECDSA(datosObra, firma, pubPintor);

        // Demostración de integridad: alterar 1 byte en memoria debe invalidar la firma
        byte[] obraAlterada = datosObra.clone();
        obraAlterada[obraAlterada.length - 1] ^= 0x01;
        boolean alteracionDetectada = !registroECDSAPort.verificarFirmaECDSA(obraAlterada, firma, pubPintor);

        String mensaje = esValida
                ? "La obra es auténtica y no sufrió ninguna modificación."
                : "[ALERTA] La firma no coincide o la obra fue alterada. No se descifrará la imagen.";

        return new ResultadoVerificacionFirma(
                obra.id(),
                obra.titulo(),
                obra.autorNombre(),
                obra.rutaImagenCifrada(),
                ALGORITMO,
                hashHex,
                obra.firmaEcdsaPintorB64(),
                llavePublicaB64.get(),
                esValida,
                esValida ? "VALIDA" : "INVALIDA",
                alteracionDetectada,
                mensaje);
    }

    private ResultadoVerificacionFirma invalida(Obra obra, String hashHex, String llavePublicaB64, String mensaje) {
        return new ResultadoVerificacionFirma(
                obra.id(),
                obra.titulo(),
                obra.autorNombre(),
                obra.rutaImagenCifrada(),
                ALGORITMO,
                hashHex,
                obra.firmaEcdsaPintorB64(),
                llavePublicaB64,
                false,
                "INVALIDA",
                false,
                mensaje);
    }

    private void validarJuez(int juezId) throws Exception {
        UsuarioInfo usuario = usuariosRepositoryPort.buscarPorId(juezId)
                .orElseThrow(() -> new IllegalArgumentException("El usuario no existe."));
        if (!"JUEZ".equalsIgnoreCase(usuario.rol())) {
            throw new SecurityException("Solo un JUEZ puede verificar la autenticidad de las obras.");
        }
    }
}
