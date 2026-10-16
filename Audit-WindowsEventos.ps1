#requires -Version 5.1
<#
.SYNOPSIS
 Auditoria de eventos Windows: sistema, actualizaciones, aplicaciones, seguridad, red o todos los registros.
.EXAMPLE
 .\Audit-WindowsEventos-30dias.ps1 -Dias 30 -Modo Todo -SinPreguntas
.EXAMPLE
 .\Audit-WindowsEventos-30dias.ps1 -Dias 30 -Modo Completo -SinPreguntas -MaximoPorRegistro 0
.NOTES
 Solo lectura; no altera registros ni configuraciones. Ejecutar elevado.
#>
[CmdletBinding()]
param(
 [ValidateRange(1,3650)][int]$Dias = 30,
 [ValidateSet('Seguridad','Sistema','Actualizaciones','Aplicaciones','Red','Todo','Completo')][string]$Modo='Todo',
 [ValidateRange(0,10000000)][int]$MaximoPorRegistro=20000,
 [string]$Salida='',
 [switch]$SinPreguntas
)
$ErrorActionPreference='Stop'
function Pregunta([string]$Titulo,[string]$Defecto) {
 $v=Read-Host "$Titulo [$Defecto]"
 if ([string]::IsNullOrWhiteSpace($v)) { return $Defecto }
 return $v.Trim()
}
function EscaparHtml([string]$s) { return [System.Net.WebUtility]::HtmlEncode($s) }
function ExportarTexto([string]$Ruta,[string[]]$Contenido) { $Contenido | Out-File -LiteralPath $Ruta -Encoding UTF8 }
$identidad=[Security.Principal.WindowsIdentity]::GetCurrent()
$admin=(New-Object Security.Principal.WindowsPrincipal($identidad)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Ejecute PowerShell como administrador.' }
if (-not $SinPreguntas) {
 Write-Host "`nAUDITORIA DE EVENTOS WINDOWS" -ForegroundColor Cyan
 Write-Host 'Modos: Seguridad | Sistema | Actualizaciones | Aplicaciones | Red | Todo | Completo'
 do { $e=Pregunta 'Modo' $Modo } until ($e -in @('Seguridad','Sistema','Actualizaciones','Aplicaciones','Red','Todo','Completo'))
 $Modo=$e
 do { $e=Pregunta 'Dias para consultar' "$Dias"; $n=0 } until ([int]::TryParse($e,[ref]$n) -and $n -ge 1 -and $n -le 3650)
 $Dias=$n
 do { $e=Pregunta 'Limite por registro (0 = sin limite)' "$MaximoPorRegistro"; $n=0 } until ([int]::TryParse($e,[ref]$n) -and $n -ge 0 -and $n -le 10000000)
 $MaximoPorRegistro=$n
}
if (-not $Salida) { $Salida=Join-Path $env:ProgramData 'AuditoriaEventosWindows' }
if (-not $SinPreguntas) { $Salida=Pregunta 'Carpeta de salida' $Salida }
$Carpeta=Join-Path $Salida ("{0}_{1}_{2}" -f $env:COMPUTERNAME,$Modo,(Get-Date -Format 'yyyyMMdd_HHmmss'))
New-Item -Path $Carpeta -ItemType Directory -Force | Out-Null
$Desde=(Get-Date).AddDays(-$Dias)
$InicioReloj=[Diagnostics.Stopwatch]::StartNew()
$LogsBase=@{
 Seguridad=@('Security')
 Sistema=@('System')
 Actualizaciones=@('Microsoft-Windows-WindowsUpdateClient/Operational','Microsoft-Windows-UpdateOrchestrator/Operational','Setup')
 Aplicaciones=@('Application')
 Red=@('Microsoft-Windows-NetworkProfile/Operational','Microsoft-Windows-Dhcp-Client/Admin','Microsoft-Windows-DNS-Client/Operational','Microsoft-Windows-WLAN-AutoConfig/Operational')
}
$Rangos=@{
 'System'=@(12,13,19,41,55,1001,1074,6005,6006,6008,6009,7031,7034,7045)
 'Application'=@(1000,1001,1026)
}
if ($Modo -eq 'Completo') {
 # Enumerar todos los registros habilitados; algunos analiticos pueden no permitir consulta: registrar aviso.
 $Logs=@(Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.IsEnabled -and $_.RecordCount -gt 0 } | Select-Object -ExpandProperty LogName -Unique)
} elseif ($Modo -eq 'Todo') {
 $Logs=@($LogsBase.Values | ForEach-Object { $_ } | Select-Object -Unique)
} else { $Logs=@($LogsBase[$Modo]) }
$Avisos=New-Object 'System.Collections.Generic.List[string]'
$Resumen=New-Object 'System.Collections.Generic.List[object]'
$Total=0
$Idx=0
foreach ($Log in $Logs) {
 $Idx++
 $ProgresoBase=[int](100*($Idx-1)/[Math]::Max(1,$Logs.Count))
 Write-Progress -Activity 'Auditoria de eventos Windows' -Status "Registro $Idx/$($Logs.Count): $Log" -PercentComplete $ProgresoBase
 Write-Host "[$Idx/$($Logs.Count)] Consultando $Log ..." -ForegroundColor Cyan
 $Contador=0
 $Errores=0
 $RutaCsv=Join-Path $Carpeta (('Eventos_'+($Log -replace '[^a-zA-Z0-9_-]','_')+'.csv'))
 $Escritor=$null
 try {
  $Escritor=New-Object System.IO.StreamWriter($RutaCsv,$false,(New-Object System.Text.UTF8Encoding($true)))
  $Escritor.WriteLine('"FechaHora";"Registro";"Origen";"ID";"Nivel";"Equipo";"RecordID";"Mensaje"')
  $Filtro=@{LogName=$Log;StartTime=$Desde}
  $Consulta=@{FilterHashtable=$Filtro;ErrorAction='Stop'}
  if ($MaximoPorRegistro -gt 0) { $Consulta.MaxEvents=$MaximoPorRegistro }
  Get-WinEvent @Consulta | ForEach-Object {
   $Ev=$_
   try {
    $Mensaje=[string]$Ev.Message
    $Cols=@(
      $Ev.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'),$Log,[string]$Ev.ProviderName,[string]$Ev.Id,
      [string]$Ev.LevelDisplayName,[string]$Ev.MachineName,[string]$Ev.RecordId,$Mensaje
    )
    $Linea=($Cols | ForEach-Object { '"'+($_ -replace '"','""')+'"' }) -join ';'
    $Escritor.WriteLine($Linea)
    $Contador++
    if (($Contador % 500) -eq 0) {
      Write-Host "  $Contador eventos procesados; $([int]$InicioReloj.Elapsed.TotalSeconds)s" -ForegroundColor DarkGray
      Write-Progress -Activity 'Auditoria de eventos Windows' -Status "$Log - $Contador eventos leidos" -PercentComplete $ProgresoBase
    }
   } catch { $Errores++ }
  }
 } catch {
  $Motivo=$_.Exception.Message
  if ($Motivo -notmatch 'NoMatchingEventsFound|No events were found|No se encontraron eventos|No se han encontrado eventos') {
    $Avisos.Add("${Log}: $Motivo")
    Write-Warning "${Log}: $Motivo"
  }
 } finally { if ($null -ne $Escritor) { $Escritor.Dispose() } }
 $Total+=$Contador
 $Resumen.Add([pscustomobject]@{Registro=$Log;Eventos=$Contador;Errores=$Errores;LimiteAlcanzado=($MaximoPorRegistro -gt 0 -and $Contador -ge $MaximoPorRegistro);Archivo=(Split-Path $RutaCsv -Leaf)})
 Write-Host "  Finalizado: $Contador eventos" -ForegroundColor Green
}
$Resumen | Export-Csv -LiteralPath (Join-Path $Carpeta 'Resumen_Registros.csv') -Delimiter ';' -NoTypeInformation -Encoding UTF8
# El resumen HTML incluye cobertura. Los CSV contienen todos los detalles y mensajes completos.
$Filas=foreach($r in $Resumen) {
 '<tr><td>'+ (EscaparHtml $r.Registro) + '</td><td>'+ $r.Eventos + '</td><td>'+ $r.Errores + '</td><td>'+ $(if($r.LimiteAlcanzado){'Si'}else{'No'}) +'</td><td>'+ (EscaparHtml $r.Archivo) +'</td></tr>'
}
$Notas=@(
 "Equipo=$env:COMPUTERNAME",
 "Fecha de ejecucion=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))",
 "Desde=$($Desde.ToString('yyyy-MM-dd HH:mm:ss'))",
 "Modo=$Modo",
 "Limite por registro=$MaximoPorRegistro",
 "Eventos exportados=$Total",
 "Segundos transcurridos=$([int]$InicioReloj.Elapsed.TotalSeconds)",
 'El limite por registro causa un resultado parcial cuando se alcanza.',
 'La ausencia de eventos puede deberse a falta de auditoria, retencion, registros deshabilitados o ausencia de actividad.',
 'Los registros de descarga de actualizaciones no siempre detallan cada descarga; instalacion y descarga son estados distintos.',
 'El evento 41 no demuestra por si solo corte electrico.',
 'Completo incluye logs habilitados accesibles; no recupera historial eliminado ni registros externos.',
 'Eventos almacenados cronologicamente como devuelve Get-WinEvent (normalmente mas recientes primero).'
)
$Notas+=@($Avisos.ToArray())
ExportarTexto (Join-Path $Carpeta 'Notas_y_Cobertura.txt') $Notas
$So=(Get-CimInstance Win32_OperatingSystem).Caption
$Html=@"
<!doctype html><html lang="es"><head><meta charset="utf-8"><title>Auditoria de eventos</title>
<style>body{font:15px Segoe UI,Arial;background:#0f172a;color:#e2e8f0;margin:36px}main{max-width:1180px;margin:auto}h1{color:#38bdf8}section{background:#1e293b;border-radius:12px;padding:22px;margin:22px 0}table{width:100%;border-collapse:collapse}td,th{padding:9px;text-align:left;border-bottom:1px solid #475569}th{color:#93c5fd}</style></head><body><main>
<h1>Auditoria de eventos Windows</h1><p>Equipo: $(EscaparHtml $env:COMPUTERNAME) | SO: $(EscaparHtml $So) | Modo: $(EscaparHtml $Modo)</p>
<p>Periodo: ultimos $Dias dias | Eventos exportados: $Total | Duracion: $([int]$InicioReloj.Elapsed.TotalSeconds) segundos</p>
<section><h2>Registros analizados</h2><table><tr><th>Registro</th><th>Eventos</th><th>Errores</th><th>Limite</th><th>CSV</th></tr>$($Filas -join "`n")</table></section>
<section><h2>Notas importantes</h2><p>Consulta de solo lectura. Los CSV contienen el detalle completo disponible de cada registro. Ver Notas_y_Cobertura.txt para advertencias y limites.</p>
<p>Investigar reinicios cruzando System (41, 6008, 1074, 1001) con WindowsUpdateClient y Setup. Un reinicio inesperado no indica necesariamente fallo de energia.</p></section></main></body></html>
"@
$Html | Out-File -LiteralPath (Join-Path $Carpeta 'Resumen_Eventos.html') -Encoding UTF8
Write-Progress -Activity 'Auditoria de eventos Windows' -Completed
Write-Host "`nCompletado: $Total eventos. Reportes: $Carpeta" -ForegroundColor Green
if (-not $SinPreguntas) { if ((Read-Host 'Abrir resumen HTML (S/N)') -match '^[sSyY]') { Start-Process (Join-Path $Carpeta 'Resumen_Eventos.html') } }
