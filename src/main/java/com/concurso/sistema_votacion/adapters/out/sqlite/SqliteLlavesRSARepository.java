package com.concurso.sistema_votacion.adapters.out.sqlite;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Repository;

import com.concurso.sistema_votacion.ports.out.LlavesRSARepositoryPort;

@Repository
public class SqliteLlavesRSARepository implements LlavesRSARepositoryPort {

    @Value("${spring.datasource.url:jdbc:sqlite:db/votacion.db}")
    private String dbUrl;

    @Override
    public boolean existeLlavePublicaPorUsuario(int usuarioId) throws Exception {
        try (Connection conn = DriverManager.getConnection(dbUrl);
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT 1 FROM LLAVES_RSA WHERE usuario_id = ?")) {
            ps.setInt(1, usuarioId);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next();
            }
        }
    }

    @Override
    public void guardarLlavePublicaUsuario(int usuarioId, String llavePublicaB64) throws Exception {
        try (Connection conn = DriverManager.getConnection(dbUrl);
                PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO LLAVES_RSA (usuario_id, llave_publica) VALUES (?, ?) " +
                        "ON CONFLICT(usuario_id) DO UPDATE SET llave_publica = excluded.llave_publica")) {
            ps.setInt(1, usuarioId);
            ps.setString(2, llavePublicaB64);
            ps.executeUpdate();
        }
    }
}

