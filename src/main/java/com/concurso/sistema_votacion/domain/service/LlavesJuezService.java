package com.concurso.sistema_votacion.domain.service;

import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Base64;

import org.springframework.stereotype.Service;

import com.concurso.sistema_votacion.ports.in.GestionLlavesJuezUseCase;
import com.concurso.sistema_votacion.ports.out.LlavesECRepositoryPort;
import com.concurso.sistema_votacion.ports.out.RegistroECDSAPort;

@Service
public class LlavesJuezService implements GestionLlavesJuezUseCase {

    private static final Path DIR_JUECES = Paths.get("claves_usuarios", "Jueces");

    private final RegistroECDSAPort registroECDSAPort;
    private final LlavesECRepositoryPort llavesECRepositoryPort;

    public LlavesJuezService(
            RegistroECDSAPort registroECDSAPort,
            LlavesECRepositoryPort llavesECRepositoryPort) {
        this.registroECDSAPort = registroECDSAPort;
        this.llavesECRepositoryPort = llavesECRepositoryPort;
    }

    @Override
    public void asegurarLlavesJuez(int usuarioId, String nombreUsuario) throws Exception {
        Path carpetaJuez = resolverCarpetaJuez(nombreUsuario);
        String nombreArchivoKey = "priv_" + formatearNombre(nombreUsuario) + ".pem";
        Path rutaLlavePrivada = carpetaJuez.resolve(nombreArchivoKey);

        boolean existeEnBD = llavesECRepositoryPort.existeLlavePublicaPorUsuario(usuarioId);
        boolean existePrivadaEnDisco = Files.exists(rutaLlavePrivada);

        // Si ya existen tanto la llave pública en BD como su llave privada en disco, se mantienen intactas
        if (existeEnBD && existePrivadaEnDisco) {
            return;
        }

        // Generar el par de llaves EC usando ModuloRegistroECDSA
        KeyPair parLlaves = registroECDSAPort.generarParLlavesECDSA();

        // Guardar llave privada en su carpeta dentro de claves_usuarios/Jueces/<NombreJuez>/
        registroECDSAPort.guardarLlavePrivada(parLlaves.getPrivate(), rutaLlavePrivada);

        // Inyectar llave pública en Base64 en la tabla LLAVES_EC de la base de datos
        String llavePublicaB64 = Base64.getEncoder().encodeToString(parLlaves.getPublic().getEncoded());
        llavesECRepositoryPort.guardarLlavePublicaUsuario(usuarioId, llavePublicaB64);
    }

    private Path resolverCarpetaJuez(String nombreUsuario) throws Exception {
        Files.createDirectories(DIR_JUECES);
        String nombreEsperado = formatearNombre(nombreUsuario);

        try (DirectoryStream<Path> stream = Files.newDirectoryStream(DIR_JUECES)) {
            for (Path subDir : stream) {
                if (Files.isDirectory(subDir)
                        && subDir.getFileName().toString().equalsIgnoreCase(nombreEsperado)) {
                    return subDir;
                }
            }
        }
        return DIR_JUECES.resolve(nombreEsperado);
    }

    private String formatearNombre(String nombreUsuario) {
        String[] partes = nombreUsuario.trim().split("\\s+");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < partes.length; i++) {
            if (partes[i].isEmpty()) continue;
            if (sb.length() > 0) sb.append("_");
            sb.append(Character.toUpperCase(partes[i].charAt(0)));
            if (partes[i].length() > 1) {
                sb.append(partes[i].substring(1).toLowerCase());
            }
        }
        return sb.toString();
    }
}

