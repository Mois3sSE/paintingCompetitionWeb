package com.concurso.sistema_votacion.ports.in;

import java.util.List;

import com.concurso.sistema_votacion.domain.model.Obra;
import com.concurso.sistema_votacion.domain.model.ResultadoFirmaObra;

/**
 * Puerto de entrada para que el Pintor registre su obra firmándola con ECDSA.
 * Integrante 2 - Registro, Identidad y No Repudio.
 */
public interface RegistroObraPintorUseCase {

    ResultadoFirmaObra registrarObraFirmada(int pintorId, String titulo,
            String nombreArchivoOriginal, byte[] obraCifrada) throws Exception;

    List<Obra> listarObrasDelPintor(int pintorId) throws Exception;
}
