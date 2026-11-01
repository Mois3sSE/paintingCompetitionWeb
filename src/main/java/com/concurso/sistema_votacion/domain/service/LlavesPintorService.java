package com.concurso.sistema_votacion.domain.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Base64;

import org.springframework.stereotype.Service;

import com.concurso.sistema_votacion.ports.in.GestionLlavesPintorUseCase;
import com.concurso.sistema_votacion.ports.out.LlavesECRepositoryPort;
import com.concurso.sistema_votacion.ports.out.RegistroECDSAPort;

@Service
public class LlavesPintorService implements GestionLlavesPintorUseCase {

    private static final Path DIR_PINTORES = Paths.get("claves_usuarios", "Pintores");

    private final RegistroECDSAPort registroECDSAPort;
    private final LlavesECRepositoryPort llavesECRepositoryPort;

    public LlavesPintorService(
            RegistroECDSAPort registroECDSAPort,
            LlavesECRepositoryPort llavesECRepositoryPort) {
        this.registroECDSAPort = registroECDSAPort;
        this.llavesECRepositoryPort = llavesECRepositoryPort;
    }

    @Override
    public void asegurarLlavesPintor(int usuarioId, String nombreUsuario) throws Exception {
        String nombreNormalizado = nombreUsuario.trim().replaceAll("\\s+", "_");
        Path carpetaPintor = DIR_PINTORES.resolve(nombreNormalizado);
        Path rutaLlavePrivada = carpetaPintor.resolve(nombreNormalizado + "_priv.pem");

        boolean existeEnBD = llavesECRepositoryPort.existeLlavePublicaPorUsuario(usuarioId);
        boolean existePrivadaEnDisco = Files.exists(rutaLlavePrivada);

        // Si ya existen tanto la llave pública en BD como su llave privada en disco, se mantienen intactas
        if (existeEnBD && existePrivadaEnDisco) {
            return;
        }

        // Crear la carpeta del pintor (ej. claves_usuarios/Pintores/NombreUsuario/)
        Files.createDirectories(carpetaPintor);

        // Generar el par de llaves EC usando ModuloRegistroECDSA
        KeyPair parLlaves = registroECDSAPort.generarParLlavesECDSA();

        // Guardar llave privada en claves_usuarios/Pintores/<NombreUsuario>/<NombreUsuario>_priv
        registroECDSAPort.guardarLlavePrivada(parLlaves.getPrivate(), rutaLlavePrivada);

        // Inyectar llave pública en Base64 en la tabla LLAVES_EC de la base de datos
        String llavePublicaB64 = Base64.getEncoder().encodeToString(parLlaves.getPublic().getEncoded());
        llavesECRepositoryPort.guardarLlavePublicaUsuario(usuarioId, llavePublicaB64);
    }
}

