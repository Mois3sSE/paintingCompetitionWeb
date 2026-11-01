package com.concurso.sistema_votacion.domain.crypto;

import com.concurso.sistema_votacion.ports.out.AnonimatoRSAPort;
import org.bouncycastle.crypto.generators.RSABlindingFactorGenerator;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Generación del factor de cegado, cegado de mensajes y
 * protocolo de firma ciega RSA (Chaum).
 */
@Component
public class ModuloAnonimatoRSA implements AnonimatoRSAPort {

    private BigInteger ultimoFactorCegado;

    public BigInteger getUltimoFactorCegado() {
        return ultimoFactorCegado;
    }

    public void setUltimoFactorCegado(BigInteger factor) {
        this.ultimoFactorCegado = factor;
    }

    @Override
    public byte[] cifrar(byte[] datos, Object clave) {
        throw new UnsupportedOperationException("El modulo de Anonimato no realiza la opreacion de cifrar.");
    }

    @Override
    public byte[] firmar(byte[] datos, Object clavePrivada) {
        return firmarCegadoRSA(datos, (RSAPrivateKey) clavePrivada);
    }

    @Override
    public byte[] cegar(byte[] datos, Object clavePublica) {
        RSAPublicKey llavePub = (RSAPublicKey) clavePublica;
        BigInteger factor = generarFactorCegado(llavePub);
        this.ultimoFactorCegado = factor;
        return cegarMensaje(datos, factor, llavePub);
    }

    @Override
    public KeyPair generarParLlavesRSA() {
        try {
            KeyPairGenerator generador = KeyPairGenerator.getInstance("RSA");
            generador.initialize(3072);
            return generador.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Error al generar llaves.");
        }
    }

    @Override
    public BigInteger generarFactorCegado(RSAPublicKey clavePublicaRSA) {
        try {
            RSAKeyParameters llavePublicaBC = new RSAKeyParameters(false,
                    clavePublicaRSA.getModulus(),
                    clavePublicaRSA.getPublicExponent());

            RSABlindingFactorGenerator generadorFactor = new RSABlindingFactorGenerator();
            SecureRandom randomSeguro = new SecureRandom();
            generadorFactor.init(new ParametersWithRandom(llavePublicaBC, randomSeguro));
            return generadorFactor.generateBlindingFactor();

        } catch (Exception e) {
            throw new RuntimeException("Error al general el factor de cegado.");
        }

    }

    @Override
    public byte[] cegarMensaje(byte[] mensaje, BigInteger factorCegado, RSAPublicKey clavePublicaRSA) {
        try {
            RSAKeyParameters llavePublicaBC = new RSAKeyParameters(false,
                    clavePublicaRSA.getModulus(),
                    clavePublicaRSA.getPublicExponent());
            RSABlindingParameters parametrosCegado = new RSABlindingParameters(llavePublicaBC, factorCegado);
            RSABlindingEngine motorCegado = new RSABlindingEngine();
            motorCegado.init(true, parametrosCegado);
            return motorCegado.processBlock(mensaje, 0, mensaje.length);
        } catch (Exception e) {
            throw new RuntimeException("Error al cegar el mensaje.");
        }
    }

    @Override
    public byte[] firmarCegadoRSA(byte[] mensajeCegado, RSAPrivateKey clavePrivadaRSA) {
        try {
            RSAKeyParameters llavePrivadaBC = new RSAKeyParameters(true,
                    clavePrivadaRSA.getModulus(),
                    clavePrivadaRSA.getPrivateExponent());

            RSAEngine motorRSA = new RSAEngine();
            motorRSA.init(true, llavePrivadaBC);
            return motorRSA.processBlock(mensajeCegado, 0, mensajeCegado.length);

        } catch (Exception e) {
            throw new RuntimeException("Error al aplicar la firma al mensaje");
        }
    }

    @Override
    public byte[] descegarFirmaRSA(byte[] firmaCegada, BigInteger factorCegado, RSAPublicKey clavePublicaRSA) {
        try {
            RSAKeyParameters llavePublicaBC = new RSAKeyParameters(false,
                    clavePublicaRSA.getModulus(),
                    clavePublicaRSA.getPublicExponent());

            RSABlindingParameters parametrosCegado = new RSABlindingParameters(llavePublicaBC, factorCegado);
            RSABlindingEngine motorCegado = new RSABlindingEngine();
            motorCegado.init(false, parametrosCegado);
            return motorCegado.processBlock(firmaCegada, 0, firmaCegada.length);
        } catch (Exception e) {
            throw new RuntimeException("Error al descegar la firma.");
        }
    }

    @Override
    public boolean verificarFirmaRSA(byte[] mensajeOriginal, byte[] firmaDescegada, RSAPublicKey clavePublicaRSA) {
        try {
            RSAKeyParameters llavePublicaBC = new RSAKeyParameters(false,
                    clavePublicaRSA.getModulus(),
                    clavePublicaRSA.getPublicExponent());
                    
            RSAEngine motorRSA = new RSAEngine();
            motorRSA.init(true, llavePublicaBC);
            byte[] mensajeRecuperado = motorRSA.processBlock(firmaDescegada, 0, firmaDescegada.length);
            return Arrays.equals(limpiarCeros(mensajeRecuperado), limpiarCeros(mensajeOriginal));
        } catch (Exception e) {
            System.err.println("Error en la verificacion de firma: " + e.getMessage());
            return false;
        }

    }

    private byte[] limpiarCeros(byte[] arreglo) {
        int i = 0;
        while (i < arreglo.length && arreglo[i] == 0) {
            i++;
        }
        return Arrays.copyOfRange(arreglo, i, arreglo.length);
    }

    // =========================================================
    // PERSISTENCIA Y CARGA DE LLAVES RSA (FIRMA CIEGA DE CHAUM)
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
    public void guardarParLlavesRSA(KeyPair parLlaves, Path rutaPublica, Path rutaPrivada) throws IOException {
        Objects.requireNonNull(parLlaves, "El par de llaves no puede ser nulo.");
        guardarLlavePublica(parLlaves.getPublic(), rutaPublica);
        guardarLlavePrivada(parLlaves.getPrivate(), rutaPrivada);
    }

    @Override
    public RSAPublicKey cargarLlavePublica(Path rutaArchivo) throws Exception {
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");
        if (!Files.exists(rutaArchivo)) {
            throw new IOException("El archivo de clave pública no existe: " + rutaArchivo);
        }

        String contenidoB64 = Files.readString(rutaArchivo, StandardCharsets.UTF_8).trim();
        byte[] bytesClave = Base64.getDecoder().decode(contenidoB64);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec spec = new X509EncodedKeySpec(bytesClave);
        return (RSAPublicKey) kf.generatePublic(spec);
    }

    @Override
    public RSAPrivateKey cargarLlavePrivada(Path rutaArchivo) throws Exception {
        Objects.requireNonNull(rutaArchivo, "La ruta de archivo no puede ser nula.");
        if (!Files.exists(rutaArchivo)) {
            throw new IOException("El archivo de clave privada no existe: " + rutaArchivo);
        }

        String contenidoB64 = Files.readString(rutaArchivo, StandardCharsets.UTF_8).trim();
        byte[] bytesClave = Base64.getDecoder().decode(contenidoB64);

        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytesClave);
        return (RSAPrivateKey) kf.generatePrivate(spec);
    }

    /**
     * Genera y guarda las llaves RSA exclusivamente para el presidente en
     * "claves_usuario/presidente" con los nombres:
     * - "nombrePresidente_RSA_pub.txt" para la llave pública
     * - "nombrePresidente_RSA_priv.txt" para la llave privada
     *
     * @param nombrePresidente Nombre de usuario del presidente
     * @return Par de llaves RSA generado
     * @throws Exception Si ocurre un error de E/S o criptográfico
     */
    public KeyPair generarYGuardarLlavesRSAPresidente(String nombrePresidente) throws Exception {
        KeyPair par = generarParLlavesRSA();
        Path dirPresidente = Paths.get("claves_usuario", "presidente");
        Files.createDirectories(dirPresidente);

        Path pathPub = dirPresidente.resolve(nombrePresidente + "_RSA_pub.txt");
        Path pathPriv = dirPresidente.resolve(nombrePresidente + "_RSA_priv.txt");

        guardarParLlavesRSA(par, pathPub, pathPriv);
        return par;
    }
}

