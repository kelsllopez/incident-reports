# INC-005 — Persistencia / Backdoor

**Ticket:** INC-005  
**Fecha:** 18 de junio de 2026 · 20:00:00  
**Analista:** Katalina Sepúlveda López  
**Severidad:** 🔴 Crítica  
**Estado:** ✅ Cerrado  
**MITRE:** T1543.003 — Windows Service  
**SIEM:** Wazuh 4.7.5  

---

## Descripción

El atacante implementó **4 mecanismos de persistencia simultáneos** para garantizar acceso continuo al sistema aunque fuera detectado y eliminado. Se creó un script malicioso camuflado como servicio legítimo de Windows (`Windows Update Helper`), una tarea programada de inicio automático y una clave de registro de ejecución automática, todos apuntando al mismo archivo `backdoor.ps1`. Wazuh detectó la actividad mediante File Integrity Monitoring (FIM) en tiempo real.

---

## Infraestructura afectada

| Campo | Valor |
|---|---|
| Hostname | WIN-J36GU3SVEOC.soc.local |
| Sistema | Windows Server 2022 Standard Evaluation |
| IP | 192.168.56.20 |
| Dominio | soc.local |
| Agente Wazuh | 001 — WindowsServer |

---

## Mecanismos de persistencia detectados

| Capa | Tipo | Nombre | Detalle |
|---|---|---|---|
| 1 | Archivo malicioso | `backdoor.ps1` | `C:\Windows\System32\backdoor.ps1` — 32 bytes |
| 2 | Servicio falso | `WindowsUpdateHelper` | Display: "Windows Update Helper" · Inicio: Automático · Cuenta: LocalSystem |
| 3 | Tarea programada | `WindowsSecurityUpdate` | Trigger: AtStartup · Nivel: Highest · Acción: powershell.exe |
| 4 | Clave de registro | `SecurityHelper` | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` |

---

## Cronología del ataque

```
20:00:00 → backdoor.ps1 creado en System32          → FIM alerta (Syscheck rule 550)
20:00:30 → Servicio WindowsUpdateHelper instalado   → EventID 7045
20:01:00 → Tarea WindowsSecurityUpdate creada       → EventID 4698
20:01:30 → Clave SecurityHelper en Registro Run     → FIM Registry (EventID 4657)
20:55:06 → Archivo de tareas modificado             → EventID 550 · hash MD5 cambió
21:00:00 → Analista detecta y contiene ✅
```

---

## Comandos ejecutados por el atacante

```powershell
# CAPA 1 — Archivo malicioso
New-Item -Path "C:\Windows\System32\backdoor.ps1" -ItemType File -Value "# Backdoor simulado para lab SOC"

# CAPA 2 — Servicio falso
New-Service -Name "WindowsUpdateHelper" `
  -BinaryPathName "C:\Windows\System32\backdoor.ps1" `
  -DisplayName "Windows Update Helper" `
  -StartupType Automatic `
  -Description "Servicio de actualizacion de Windows"

# CAPA 3 — Tarea programada
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File C:\Windows\System32\backdoor.ps1"
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName "WindowsSecurityUpdate" -Action $action -Trigger $trigger -RunLevel Highest -Force

# CAPA 4 — Registro Run
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" `
  -Name "SecurityHelper" `
  -Value "C:\Windows\System32\backdoor.ps1" `
  -PropertyType String -Force

# Verificación final
Get-Service "WindowsUpdateHelper"
Get-ScheduledTask "WindowsSecurityUpdate"
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

**Resultado verificación registro:**
```
SecurityHealth : C:\Windows\system32\SecurityHealthSystray.exe
VBoxTray       : C:\Windows\system32\VBoxTray.exe
SecurityHelper : C:\Windows\System32\backdoor.ps1   ← MALICIOSO
```

---

## Configuración FIM implementada en Wazuh

```xml
<agent_config>
  <syscheck>
    <directories check_all="yes" realtime="yes">C:\Windows\System32</directories>
    <directories check_all="yes" realtime="yes">C:\Windows\System32\Tasks</directories>
    <registry_check>
      <registry>HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run</registry>
    </registry_check>
  </syscheck>
</agent_config>
```

---

## Evidencia Wazuh

### FIM — Archivo creado
```json
{
  "rule": { "id": 550, "description": "Integrity checksum changed.", "level": 7 },
  "syscheck": {
    "event": "added",
    "path": "c:\\windows\\system32\\backdoor.ps1",
    "mode": "realtime"
  }
}
```

### EventID 7045 — Servicio instalado
```json
{
  "eventID": 7045,
  "serviceName": "Windows Update Helper",
  "imagePath": "C:\\Windows\\System32\\backdoor.ps1",
  "accountName": "LocalSystem",
  "startType": "inicio automático",
  "rule": { "id": 61138, "level": 5 },
  "mitre": { "id": "T1543.003", "tactic": "Persistence, Privilege Escalation" }
}
```

### EventID 4698 — Tarea programada creada
```json
{
  "eventID": 4698,
  "taskName": "WindowsSecurityUpdate",
  "subjectUserName": "Administrador",
  "mitre": "T1053.005 - Scheduled Task"
}
```

### FIM Registry — Registro modificado
```json
{
  "eventID": 4657,
  "objectName": "SecurityHelper",
  "objectValue": "C:\\Windows\\System32\\backdoor.ps1",
  "subjectUserName": "Administrador",
  "mitre": "T1547.001 - Registry Run Keys"
}
```

### EventID 550 — Archivo modificado (Tasks)
```json
{
  "rule": { "id": 550, "description": "Integrity checksum changed.", "level": 7 },
  "syscheck": {
    "event": "modified",
    "path": "c:\\windows\\system32\\tasks\\microsoft\\windows\\softwareprotectionplatform\\svcrestarttask",
    "mode": "realtime",
    "changed_attributes": "mtime, md5, sha1, sha256"
  },
  "timestamp": "Jun 17, 2026 @ 20:55:06.735"
}
```

---

## Indicadores de compromiso (IOC)

| IOC | Tipo | Valor |
|---|---|---|
| Archivo malicioso | Ruta | `C:\Windows\System32\backdoor.ps1` |
| Servicio falso | Nombre | `WindowsUpdateHelper` |
| Tarea programada | Nombre | `WindowsSecurityUpdate` |
| Clave de registro | Nombre | `SecurityHelper` en HKLM Run |
| Hash MD5 (Tasks) | Hash | cambió de `ffab8f` a `a6a582` |

---

## Técnicas MITRE ATT&CK

| ID | Técnica | Táctica | Descripción |
|---|---|---|---|
| T1543.003 | Windows Service | Persistence · Privilege Escalation | Servicio falso `WindowsUpdateHelper` |
| T1053.005 | Scheduled Task | Persistence | Tarea `WindowsSecurityUpdate` |
| T1547.001 | Registry Run Keys | Persistence | Clave `SecurityHelper` en Run |
| T1036 | Masquerading | Defense Evasion | Nombres que imitan servicios legítimos de Windows |
| T1565.001 | Stored Data Manipulation | Impact | Modificación de archivos del sistema |

---

## Impacto

- 🔴 Acceso persistente aunque se cambien contraseñas
- 🔴 Ejecución automática en cada inicio de Windows
- 🔴 Camuflado como servicio legítimo ("Windows Update Helper")
- 🔴 Múltiples capas de resiliencia (4 mecanismos diferentes)
- 🔴 Ejecución con máximos privilegios (LocalSystem)

---

## Acciones de contención

```powershell
# 1. Eliminar archivo malicioso
Remove-Item "C:\Windows\System32\backdoor.ps1" -Force

# 2. Detener y eliminar servicio
Stop-Service "WindowsUpdateHelper" -Force
sc.exe delete "WindowsUpdateHelper"
# Salida esperada: [SC] DeleteService CORRECTO

# 3. Eliminar tarea programada
Unregister-ScheduledTask -TaskName "WindowsSecurityUpdate" -Confirm:$false

# 4. Limpiar registro
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHelper" -Force

# 5. Verificar eliminación
Test-Path "C:\Windows\System32\backdoor.ps1"
# Resultado esperado: False
```

**Verificación en Wazuh FIM:**
```
rule.groups: syscheck
→ Eventos de archivo eliminado ✅
→ Eventos de registro eliminado ✅
```

---

## Resumen ejecutivo de contención

| Acción | Resultado |
|---|---|
| Amenaza contenida | ✅ Sí |
| Archivo eliminado | ✅ Sí |
| Servicio eliminado | ✅ Sí |
| Tarea eliminada | ✅ Sí |
| Registro eliminado | ✅ Sí |
| Logs preservados | ✅ Sí (Wazuh) |
| Estado final | 🟢 SISTEMA LIMPIO |

---

## Tabla de técnicas de persistencia — Referencia

| Técnica | MITRE | Cómo detectar en Wazuh |
|---|---|---|
| Servicio falso | T1543.003 | EventID 7045 |
| Tarea programada | T1053.005 | EventID 4698 |
| Registro Run | T1547.001 | FIM Registry |
| Archivo en System32 | T1036 | FIM archivos |
| Startup folder | T1547.001 | FIM carpetas |
| DLL Hijacking | T1574 | FIM + Sysmon |

---

## Recomendaciones

### 🔴 Alta Prioridad
1. Auditar TODOS los servicios instalados en el sistema
2. Revisar todas las tareas programadas en busca de nombres sospechosos
3. Auditar claves de registro Run/RunOnce en HKLM y HKCU
4. Implementar monitoreo continuo con FIM para System32 y Tasks

### 🟡 Media Prioridad
5. Implementar Application Whitelisting (solo ejecutables autorizados)
6. Alertas automáticas para EventID 7045 (nuevos servicios)
7. Alertas automáticas para EventID 4698 (nuevas tareas programadas)
8. Reglas Wazuh para monitorear creación de archivos `.ps1` en System32

### 🟢 Baja Prioridad
9. Revisar política de instalación de servicios
10. Implementar MFA para cuentas administrativas
11. Realizar pentesting periódico de persistencia

---

## Lecciones aprendidas

- **FIM es crítico** para detectar persistencia en tiempo real
- Nombres de servicios que imitan Windows son señal de alerta inmediata
- Siempre auditar Run keys después de cualquier incidente
- La persistencia puede sobrevivir a cambios de contraseña
- Múltiples capas hacen más difícil la eliminación completa de un backdoor
- Syscheck detecta modificaciones en archivos del sistema inmediatamente

---

## Cierre formal

| Campo | Valor |
|---|---|
| Estado | CONTENIDO ✅ |
| Ticket | INC-005 |
| Escalamiento | Reportado a SOC Tier 2 |
| Compromisos confirmados | 0 |

*Documento clasificado como CONFIDENCIAL — Solo uso interno del SOC*

---

**Firma:** Katalina Sepúlveda López — Analista SOC Nivel 1 — CyberCorp S.A.  
**Fecha:** 18 de junio de 2026
