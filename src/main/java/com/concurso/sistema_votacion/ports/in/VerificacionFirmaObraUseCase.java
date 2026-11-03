package com.concurso.sistema_votacion.ports.in;

import java.util.List;

import com.concurso.sistema_votacion.domain.model.Obra;
import com.concurso.sistema_votacion.domain.model.ResultadoVerificacionFirma;

/**
 * Puerto de entrada para que el Juez verifique la autenticidad (ECDSA) de las obras.
 * Integrante 2 - Registro, Identidad y No Repudio.
 */
public interface VerificacionFirmaObraUseCase {

    List<Obra> listarObrasParaJuez(int juezId) throws Exception;

    ResultadoVerificacionFirma verificarFirmaObra(int juezId, int obraId) throws Exception;
}
