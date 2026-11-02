package com.concurso.sistema_votacion.domain.service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;

import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Service;

import com.concurso.sistema_votacion.ports.in.InicializarLlavesSistemaUseCase;
import com.concurso.sistema_votacion.ports.out.RegistroECDSAPort;

/**
 * Servicio de dominio encargado de generar y asegurar las llaves EC del Sistema
 * en la carpeta "clave_sistema" con los nombres "pub_sist" y "priv_sist".
 */
@Service
public class LlavesSistemaService implements InicializarLlavesSistemaUseCase, CommandLineRunner {

    private static final Path RUTA_PUB_SIST = Paths.get("clave_sistema", "pub_sist.pem");
    private static final Path RUTA_PRIV_SIST = Paths.get("clave_sistema", "priv_sist.pem");

    private final RegistroECDSAPort registroECDSAPort;

    public LlavesSistemaService(RegistroECDSAPort registroECDSAPort) {
        this.registroECDSAPort = registroECDSAPort;
    }

    @Override
    public void run(String... args) throws Exception {
        asegurarLlavesSistema();
    }

    @Override
    public void asegurarLlavesSistema() throws Exception {
        if (!Files.exists(RUTA_PUB_SIST) || !Files.exists(RUTA_PRIV_SIST)) {
            KeyPair parLlaves = registroECDSAPort.generarParLlavesECDSA();
            registroECDSAPort.guardarLlavePublica(parLlaves.getPublic(), RUTA_PUB_SIST);
            registroECDSAPort.guardarLlavePrivada(parLlaves.getPrivate(), RUTA_PRIV_SIST);
        }
    }
}

