package com.concurso.sistema_votacion.ports.out;

/**
 * Puerto de salida para almacenar y consultar llaves públicas RSA en la base de datos.
 */
public interface LlavesRSARepositoryPort {

    boolean existeLlavePublicaPorUsuario(int usuarioId) throws Exception;

    void guardarLlavePublicaUsuario(int usuarioId, String llavePublicaB64) throws Exception;
}

