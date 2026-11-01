package com.concurso.sistema_votacion.ports.out;

/**
 * Puerto genérico para operaciones criptográficas del sistema.
 */
public interface MotorCriptograficoPort {

    byte[] cifrar(byte[] datos, Object clave);

    byte[] firmar(byte[] datos, Object clavePrivada);

    byte[] cegar(byte[] datos, Object clavePublica);
}

