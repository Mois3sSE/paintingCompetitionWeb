package com.concurso.sistema_votacion.ports.out;

/**
 * Puerto de salida para almacenar y consultar llaves públicas EC en la base de datos.
 */
public interface LlavesECRepositoryPort {

    boolean existeLlavePublicaPorUsuario(int usuarioId) throws Exception;

    void guardarLlavePublicaUsuario(int usuarioId, String llavePublicaB64) throws Exception;
}

