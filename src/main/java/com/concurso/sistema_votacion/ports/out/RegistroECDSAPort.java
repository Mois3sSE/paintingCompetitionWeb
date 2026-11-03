package com.concurso.sistema_votacion.ports.out;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Puerto especializado para las operaciones de autenticidad ECDSA.
 * Modulo de Registro.
 *
 * Permite utilizar el modulo ECDSA sin depender
 * directamente de su adaptador de infraestructura.
 */
public interface RegistroECDSAPort extends MotorCriptograficoPort {

    // Generacion de llaves ECDSA
    KeyPair generarParLlavesECDSA();

    // Firma digital del registro
    byte[] firmarECDSA(byte[] mensaje, PrivateKey clavePrivada);

    // Verificacion de firma digital
    boolean verificarFirmaECDSA(
            byte[] mensaje,
            byte[] firma,
            PublicKey clavePublica);

    // Persistencia y carga de llaves EC
    void guardarLlavePublica(PublicKey clavePublica, Path rutaArchivo) throws Exception;

    void guardarLlavePrivada(PrivateKey clavePrivada, Path rutaArchivo) throws Exception;

    PublicKey cargarLlavePublica(Path rutaArchivo) throws Exception;

    PrivateKey cargarLlavePrivada(Path rutaArchivo) throws Exception;

    // Persistencia y carga de firmas digitales ECDSA
    void guardarFirmaDigital(byte[] firma, Path rutaArchivo) throws Exception;

    byte[] cargarFirmaDigital(Path rutaArchivo) throws Exception;
}

