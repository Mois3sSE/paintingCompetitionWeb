package com.concurso.sistema_votacion.ports.out;

import java.math.BigInteger;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Puerto especializado para las operaciones RSA y Firma a Ciegas de Chaum.
 */
public interface AnonimatoRSAPort extends MotorCriptograficoPort {

    KeyPair generarParLlavesRSA();

    BigInteger generarFactorCegado(RSAPublicKey clavePublicaRSA);

    byte[] cegarMensaje(byte[] mensaje, BigInteger factorCegado, RSAPublicKey clavePublicaRSA);

    byte[] firmarCegadoRSA(byte[] mensajeCegado, RSAPrivateKey clavePrivadaRSA);

    byte[] descegarFirmaRSA(byte[] firmaCegada, BigInteger factorCegado, RSAPublicKey clavePublicaRSA);

    boolean verificarFirmaRSA(byte[] mensajeOriginal, byte[] firmaDescegada, RSAPublicKey clavePublicaRSA);

    void guardarLlavePublica(PublicKey clavePublica, Path rutaArchivo) throws Exception;

    void guardarLlavePrivada(PrivateKey clavePrivada, Path rutaArchivo) throws Exception;

    void guardarParLlavesRSA(KeyPair parLlaves, Path rutaPublica, Path rutaPrivada) throws Exception;

    RSAPublicKey cargarLlavePublica(Path rutaArchivo) throws Exception;

    RSAPrivateKey cargarLlavePrivada(Path rutaArchivo) throws Exception;
}

