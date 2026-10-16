# Windows Event Log Incident & System Auditor (PowerShell)

Herramienta forense y de triaje de **solo lectura** en PowerShell para auditar, diagnosticar y correlacionar incidentes en Windows (Client 10/11 y Server 2012/2016/2019/2022/2025).

A diferencia de consultas convencionales que cargan colecciones masivas en memoria, este script procesa los eventos mediante streams de lectura/escritura (`System.IO.StreamWriter`) volcando directamente a disco en formato CSV delimitado por `;`, lo que protege la memoria RAM en servidores en producción con alta transaccionalidad.

---

## 🎯 Modos de Análisis Disponibles

El parámetro `-Modo` permite segmentar la recolección según el tipo de incidente:

| Modo | Canales de Registro Consultados | Objetivo Principal |
| :--- | :--- | :--- |
| **Seguridad** | `Security` | Intentos de inicio de sesión fallidos/exitosos, IPs remotas, creación/modificación de cuentas y privilegios. |
| **Sistema** | `System` | Apagados imprevistos, reinicios (Kernel-Power 41, 6008, 1074), errores de hardware, controladores y servicios. |
| **Actualizaciones** | `WindowsUpdateClient/Operational`, `UpdateOrchestrator/Operational`, `Setup` | Historial de parches, fallos de instalación/descarga y reinicios programados. |
| **Aplicaciones** | `Application` | Crashes de software (`1000`), excepciones de runtime en .NET (`1026`) y cuelgues. |
| **Red** | `NetworkProfile/Operational`, `Dhcp-Client/Admin`, `DNS-Client/Operational`, `WLAN-AutoConfig/Operational` | Caídas de enlace, renovaciones DHCP, eventos DNS y reconexiones inalámbricas. |
| **Todo** | Todos los anteriores combinados | Auditoría estándar cruzada de los 5 vectores principales. |
| **Completo** | Todos los registros habilitados con eventos en el equipo | Extracción total de cada log activo en el Visor de Eventos para peritajes exhaustivos. |

---

## 🚀 Ejemplos de Ejecución

Abre PowerShell como **Administrador**:

```powershell
# 1. Auditoría estándar recomendada (30 días, todos los vectores clave)
.\Audit-WindowsEventos.ps1 -Dias 30 -Modo Todo -SinPreguntas

# 2. Diagnóstico exclusivo de apagados, cuelgues y reinicios
.\Audit-WindowsEventos.ps1 -Dias 30 -Modo Sistema -SinPreguntas

# 3. Trazabilidad de parches y fallos de Windows Update
.\Audit-WindowsEventos.ps1 -Dias 30 -Modo Actualizaciones -SinPreguntas

# 4. Volcado total de todos los logs habilitados del sistema (sin límite de eventos)
.\Audit-WindowsEventos.ps1 -Dias 30 -Modo Completo -SinPreguntas -MaximoPorRegistro 0

💡 Consejo para diagnóstico de caídas:

Cuando investigues reinicios inesperados o pantallas azules, inicia correlacionando Sistema y Actualizaciones. Cruzar eventos de System (41, 6008, 1074, 1001) con la marca de tiempo de WindowsUpdateClient permite confirmar si el reinicio fue derivado de un parche reciente o una anomalía eléctrica/hardware.

📂 Archivos Generados en la Salida
El script organiza los resultados dentro de %ProgramData%\AuditoriaEventosWindows\<EQUIPO>_<MODO>_<TIMESTAMP>\:

Eventos_<NombreCanal>.csv: Un archivo CSV por cada canal analizado con el mensaje completo del evento, origen, ID, nivel de severidad y fecha/hora.

Resumen_Registros.csv: Tabla de control con la cantidad de eventos procesados por log, errores de lectura y advertencia de límite alcanzado.

Resumen_Eventos.html: Dashboard visual en modo oscuro para revisión rápida y presentación de resultados a clientes o directivos.

Notas_y_Cobertura.txt: Metadatos de la corrida, tiempos transcurridos y consideraciones forenses para evitar falsos positivos.

🛡️ Notas Técnicas y Buenas Prácticas
Solo lectura: No altera directivas, no borra registros ni modifica la configuración del sistema.

Retención: No recupera eventos previamente sobrescritos si el tamaño máximo configurado en el canal de Windows ya fue superado.

Consumo: Cuenta con indicador de avance en consola cada 500 registros y límite preventivo configurable (-MaximoPorRegistro, 20.000 por defecto).
