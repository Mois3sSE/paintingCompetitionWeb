@echo off
REM Ejecuta el proyecto integrado con Java 21 en http://localhost:8082
cd /d "%~dp0"
set "JAVA_HOME=C:\Users\duare\.jdks\jbr-21.0.11"
echo Iniciando servidor... cuando aparezca "Started SistemaVotacionApplication" abra http://localhost:8082
call "%~dp0mvnw.cmd" spring-boot:run
pause
