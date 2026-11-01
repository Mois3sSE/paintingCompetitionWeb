package com.concurso.sistema_votacion.domain.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.util.Base64;

import org.springframework.stereotype.Service;

import com.concurso.sistema_votacion.ports.in.GestionLlavesPresidenteUseCase;
import com.concurso.sistema_votacion.ports.out.AnonimatoRSAPort;
import com.concurso.sistema_votacion.ports.out.LlavesRSARepositoryPort;

@Service
public class LlavesPresidenteService implements GestionLlavesPresidenteUseCase {

    private static final Path RUTA_PRIV_PRESIDENTE = Paths.get("claves_usuarios", "Presidente", "priv_Presidente.pem");

    private final AnonimatoRSAPort anonimatoRSAPort;
    private final LlavesRSARepositoryPort llavesRSARepositoryPort;

    public LlavesPresidenteService(
            AnonimatoRSAPort anonimatoRSAPort,
            LlavesRSARepositoryPort llavesRSARepositoryPort) {
        this.anonimatoRSAPort = anonimatoRSAPort;
        this.llavesRSARepositoryPort = llavesRSARepositoryPort;
    }

    @Override
    public void asegurarLlavesPresidente(int usuarioId) throws Exception {
        boolean existeEnBD = llavesRSARepositoryPort.existeLlavePublicaPorUsuario(usuarioId);
        boolean existePrivadaEnDisco = Files.exists(RUTA_PRIV_PRESIDENTE);

        // Si ya existen tanto la llave pública RSA en BD como la privada en disco, se mantienen
        if (existeEnBD && existePrivadaEnDisco) {
            return;
        }

        // Generar el par de llaves RSA de 3072 bits usando ModuloAnonimatoRSA
        KeyPair parLlavesRSA = anonimatoRSAPort.generarParLlavesRSA();

        // Guardar llave privada en claves_usuarios/Presidente/priv_Presidente.pem
        anonimatoRSAPort.guardarLlavePrivada(parLlavesRSA.getPrivate(), RUTA_PRIV_PRESIDENTE);

        // Inyectar llave pública RSA en Base64 en la tabla LLAVES_RSA de la base de datos
        String llavePublicaB64 = Base64.getEncoder().encodeToString(parLlavesRSA.getPublic().getEncoded());
        llavesRSARepositoryPort.guardarLlavePublicaUsuario(usuarioId, llavePublicaB64);
    }
}

