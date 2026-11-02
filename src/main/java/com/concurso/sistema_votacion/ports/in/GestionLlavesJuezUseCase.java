package com.concurso.sistema_votacion.ports.in;

/**
 * Puerto de entrada para la gestión de llaves EC de los Jueces.
 */
public interface GestionLlavesJuezUseCase {

    void asegurarLlavesJuez(int usuarioId, String nombreUsuario) throws Exception;
}

