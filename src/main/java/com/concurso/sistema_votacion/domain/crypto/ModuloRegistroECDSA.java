package com.concurso.sistema_votacion.domain.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import com.concurso.sistema_votacion.ports.out.RegistroECDSAPort;

/**
 * Adaptador de Salida para Autenticidad, Registro y No Repudio.
 * Asignado a: INTEGRANTE 2.
 *
 * Responsabilidad:
 * - Generar pares de llaves ECDSA.
 * - Firmar digitalmente datos.
 * - Verificar firmas digitales.
 *
 * Curva: secp256r1 (NIST P-256).
 * Firma: SHA256withECDSA.
 * Proveedor: Bouncy Castle.
 */
@Component
public class ModuloRegistroECDSA implements RegistroECDSAPort {

    private static final String CURVA = "secp256r1";
    private static final String ALGORITMO_FIRMA = "SHA256withECDSA";

    private static final Provider PROVEEDOR_BC = new BouncyCastleProvider();

    // =========================================================
    // IMPLEMENTACION DEL PUERTO GENERICO
    // =========================================================

    @Override
    public byte[] cifrar(byte[] datos, Object clave) {
        // Operacion fuera del alcance del modulo ECDSA.
        return null;
    }

    @Override
    public byte[] firmar(byte[] datos, Object clavePrivada) {

        if (!(clavePrivada instanceof PrivateKey)) {
            throw new IllegalArgumentException(
                    "Se requiere una llave privada valida.");
        }

        // Delegar al metodo especifico de ECDSA.
        return firmarECDSA(datos, (PrivateKey) clavePrivada);
    }

    @Override
    public byte[] cegar(byte[] datos, Object clavePublica) {
        // Operacion fuera del alcance del modulo ECDSA.
        return null;
    }

    // =========================================================
    // METODOS ESPECIFICOS - INTEGRANTE 2
    // =========================================================

    /**
     * Genera un par de llaves publica y privada ECDSA
     * utilizando la curva secp256r1.
     *
     * @return Par de llaves generado.
     */
    @Override
    public KeyPair generarParLlavesECDSA() {

        try {

            KeyPairGenerator generador = KeyPairGenerator.getInstance(
                    "EC", PROVEEDOR_BC);

            ECGenParameterSpec parametros = new ECGenParameterSpec(CURVA);

            generador.initialize(
                    parametros,
                    new SecureRandom());

            return generador.generateKeyPair();

        } catch (GeneralSecurityException e) {

            throw new IllegalStateException(
                    "Error al generar las llaves ECDSA.", e);
        }
    }

    /**
     * Firma digitalmente los datos utilizando SHA-256 y ECDSA.
     *
     * @param mensaje      Bytes del mensaje o archivo a firmar.
     * @param clavePrivada Llave privada del Pintor.
     * @return Firma digital en bytes.
     */
    @Override
    public byte[] firmarECDSA(
            byte[] mensaje,
            PrivateKey clavePrivada) {

        Objects.requireNonNull(
                mensaje, "El mensaje no puede ser null.");

        Objects.requireNonNull(
                clavePrivada, "La llave privada no puede ser null.");

        try {

            Signature firmador = Signature.getInstance(
                    ALGORITMO_FIRMA,
                    PROVEEDOR_BC);

            // Inicializar con la llave privada del Pintor.
            firmador.initSign(
                    clavePrivada,
                    new SecureRandom());

            // SHA256withECDSA calcula el hash internamente.
            firmador.update(mensaje);

            // Generar la firma digital.
            return firmador.sign();

        } catch (GeneralSecurityException e) {

            throw new IllegalStateException(
                    "Error al generar la firma ECDSA.", e);
        }
    }

    /**
     * Verifica la autenticidad e integridad de una firma.
     *
     * @param mensaje      Datos originales que fueron firmados.
     * @param firma        Firma digital recibida.
     * @param clavePublica Llave publica del firmante.
     * @return true si la firma es valida; false si no lo es.
     */
    @Override
    public boolean verificarFirmaECDSA(
            byte[] mensaje,
            byte[] firma,
            PublicKey clavePublica) {

        Objects.requireNonNull(
                mensaje, "El mensaje no puede ser null.");

        Objects.requireNonNull(
                firma, "La firma no puede ser null.");

        Objects.requireNonNull(
                clavePublica, "La llave publica no puede ser null.");

        try {

            Signature verificador = Signature.getInstance(
                    ALGORITMO_FIRMA,
                    PROVEEDOR_BC);

            // Inicializar con la llave publica del Pintor.
            verificador.initVerify(clavePublica);

            // Procesar los mismos bytes que fueron firmados.
            verificador.update(mensaje);

            // Verificar la firma.
            return verificador.verify(firma);

        } catch (SignatureException e) {

            // Una firma malformada tambien es invalida.
            return false;

        } catch (GeneralSecurityException e) {

            throw new IllegalStateException(
                    "Error al verificar la firma ECDSA.", e);
        }
    }

    // =========================================================
    // PERSISTENCIA Y CARGA DE LLAVES EC (INTEGRANTE 2)
    // =========================================================

    @Override
    public void guardarLlavePublica(PublicKey clavePublica, Path rutaArchivo) throws IOException {
        Objects.requireNonNull(clavePublica, "La clave pública no puede ser nula.");
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");

        if (rutaArchivo.getParent() != null) {
            Files.createDirectories(rutaArchivo.getParent());
        }
        String b64 = Base64.getEncoder().encodeToString(clavePublica.getEncoded());
        Files.writeString(rutaArchivo, b64, StandardCharsets.UTF_8);
    }

    @Override
    public void guardarLlavePrivada(PrivateKey clavePrivada, Path rutaArchivo) throws IOException {
        Objects.requireNonNull(clavePrivada, "La clave privada no puede ser nula.");
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");

        if (rutaArchivo.getParent() != null) {
            Files.createDirectories(rutaArchivo.getParent());
        }
        String b64 = Base64.getEncoder().encodeToString(clavePrivada.getEncoded());
        Files.writeString(rutaArchivo, b64, StandardCharsets.UTF_8);
    }

    @Override
    public PublicKey cargarLlavePublica(Path rutaArchivo) throws Exception {
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");
        if (!Files.exists(rutaArchivo)) {
            throw new IOException("El archivo de clave pública no existe: " + rutaArchivo);
        }
        String contenido = Files.readString(rutaArchivo, StandardCharsets.UTF_8).trim();
        byte[] bytes = Base64.getDecoder().decode(contenido);
        KeyFactory kf = KeyFactory.getInstance("EC", PROVEEDOR_BC);
        return kf.generatePublic(new X509EncodedKeySpec(bytes));
    }

    @Override
    public PrivateKey cargarLlavePrivada(Path rutaArchivo) throws Exception {
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");
        if (!Files.exists(rutaArchivo)) {
            throw new IOException("El archivo de clave privada no existe: " + rutaArchivo);
        }
        String contenido = Files.readString(rutaArchivo, StandardCharsets.UTF_8).trim();
        byte[] bytes = Base64.getDecoder().decode(contenido);
        KeyFactory kf = KeyFactory.getInstance("EC", PROVEEDOR_BC);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    // =========================================================
    // PERSISTENCIA Y CARGA DE FIRMAS DIGITALES ECDSA (INTEGRANTE 2)
    // =========================================================

    @Override
    public void guardarFirmaDigital(byte[] firma, Path rutaArchivo) throws IOException {
        Objects.requireNonNull(firma, "La firma digital no puede ser nula.");
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");

        if (rutaArchivo.getParent() != null) {
            Files.createDirectories(rutaArchivo.getParent());
        }
        String b64 = Base64.getEncoder().encodeToString(firma);
        Files.writeString(rutaArchivo, b64, StandardCharsets.UTF_8);
    }

    @Override
    public byte[] cargarFirmaDigital(Path rutaArchivo) throws Exception {
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");
        if (!Files.exists(rutaArchivo)) {
            throw new IOException("El archivo de firma digital no existe: " + rutaArchivo);
        }
        String contenido = Files.readString(rutaArchivo, StandardCharsets.UTF_8).trim();
        return Base64.getDecoder().decode(contenido);
    }
}

