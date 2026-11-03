package com.concurso.sistema_votacion.domain.model;

/**
 * Resultado del análisis de autenticidad e integridad (ECDSA) que hace el Juez
 * sobre una obra registrada.
 *
 * @param resultado                 "VALIDA" o "INVALIDA".
 * @param pruebaAlteracionDetectada true si al alterar 1 byte de la obra en memoria
 *                                  la firma deja de ser válida (demostración de integridad).
 */
public record ResultadoVerificacionFirma(
        int obraId,
        String titulo,
        String pintor,
        String rutaImagenCifrada,
        String algoritmo,
        String hashSha256Hex,
        String firmaBase64,
        String llavePublicaPintorB64,
        boolean valida,
        String resultado,
        boolean pruebaAlteracionDetectada,
        String mensaje) {
}
