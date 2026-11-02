package com.concurso.sistema_votacion.ports.in;

/**
 * Puerto de entrada para la gestión de llaves RSA del Presidente.
 */
public interface GestionLlavesPresidenteUseCase {

    void asegurarLlavesPresidente(int usuarioId) throws Exception;
}

