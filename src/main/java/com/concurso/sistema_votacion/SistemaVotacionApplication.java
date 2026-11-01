package com.concurso.sistema_votacion;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class SistemaVotacionApplication {

	public static void main(String[] args) {
		SpringApplication.run(SistemaVotacionApplication.class, args);
	}

	@GetMapping("/")
	public String inicio() {
		return "El sistema de votación está funcionando correctamente.";
	}

}
