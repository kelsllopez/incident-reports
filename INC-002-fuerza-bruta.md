# INC-002 — Ataque de Fuerza Bruta

**Ticket:** INC-002  
**Fecha:** 11 de junio de 2026 · 16:32:44  
**Analista:** Katalina Sepúlveda López  
**Severidad:** 🔴 Alta  
**Estado:** ✅ Cerrado  
**MITRE:** T1110 — Brute Force  
**SIEM:** Wazuh 4.7.5  

---

## Descripción

Se detectaron múltiples intentos de autenticación fallidos contra el servicio SMB del servidor Windows (`192.168.56.20`) provenientes desde `192.168.56.30` (Kali Linux). Los intentos utilizaron el usuario `usuarioprueba` con diferentes contraseñas, indicando un ataque de fuerza bruta automatizado contra el puerto 445. El ataque fue detectado a tiempo por Wazuh. No se comprometió ninguna cuenta.

---

## Infraestructura afectada

| Activo | IP | Rol |
|---|---|---|
| WIN-J36GU3SVEOC | 192.168.56.20 | Víctima — Windows Server 2022 |
| kali-linux | 192.168.56.30 | Atacante |

---

## Cronología del ataque

```
16:32:44 → Inicio del ataque de fuerza bruta desde 192.168.56.30
16:32:44 → 20+ intentos fallidos de autenticación SMB en menos de 2 minutos
16:32:44 → Wazuh detecta y registra eventos EventID 4625 (rule 60122)
```

---

## Comandos ejecutados por el atacante

```bash
# Intento individual
smbclient -L //192.168.56.20 -U usuarioprueba --password=contraseñafalsa

# Loop automatizado (20 intentos)
for i in {1..20}; do
  smbclient -L //192.168.56.20 -U usuarioprueba --password=incorrecta$i
done
```

> Nota: Debido a restricciones de SMB en Windows Server 2022, se utilizó `smbclient` como alternativa a Hydra para generar los intentos fallidos de autenticación.

---

## Evidencia Wazuh

| Campo | Valor |
|---|---|
| Regla Wazuh | 60122 — Logon Failure / Unknown user or bad password |
| EventID | 4625 — Login Fallido |
| Nivel Wazuh | 5 |
| IP atacante | 192.168.56.30 (Kali Linux) |
| Usuario objetivo | usuarioprueba |
| Cantidad de intentos | 20+ en menos de 2 minutos |
| Hora inicio | 16:32:44 |
| Timestamp Wazuh | Jun 6, 2026 @ 16:32:44 |
| Resultado | ❌ Ataque fallido — Sin acceso |

**Filtro usado en Wazuh:**
```
rule.id: 60122
data.win.system.eventID: 4625
```

---

## Indicadores de compromiso (IOC)

| IOC | Tipo | Valor |
|---|---|---|
| IP atacante | Dirección IP | 192.168.56.30 |
| Usuario objetivo | Cuenta | usuarioprueba |
| Puerto atacado | Puerto | 445 (SMB) |
| Hora del ataque | Timestamp | 16:32:44 Jun 6 2026 |
| Regla disparada | Rule ID | 60122 |

---

## Técnicas MITRE ATT&CK

| ID | Técnica | Descripción |
|---|---|---|
| T1110 | Brute Force | Múltiples intentos de autenticación con contraseñas distintas |
| T1110.003 | Password Spraying | Intentos con usuario conocido y contraseñas variadas |

---

## Acciones de contención

```powershell
# Bloquear IP atacante en firewall de Windows Server
New-NetFirewallRule -DisplayName "Bloqueo IP atacante fuerza bruta" `
  -Direction Inbound `
  -RemoteAddress 192.168.56.30 `
  -Action Block
```

---

## Recomendaciones

| Prioridad | Acción |
|---|---|
| 🔴 Alta | Bloquear permanentemente IP 192.168.56.30 en firewall |
| 🔴 Alta | Configurar Account Lockout Policy (bloqueo tras 5 intentos fallidos) |
| 🟡 Media | Cambiar contraseña del usuario `usuarioprueba` |
| 🟡 Media | Implementar alerta automática Wazuh para 5+ EventID 4625 en 2 minutos |
| 🟢 Baja | Monitorear futuros eventos con regla 60122 |

---

## Cierre formal

| Campo | Valor |
|---|---|
| Estado | CONTENIDO ✅ |
| Ticket | INC-002 |
| Escalamiento | No requerido |
| Compromisos confirmados | 0 |

---

**Firma:** Katalina Sepúlveda López — Analista SOC Nivel 1 — CyberCorp S.A.  
**Fecha:** 11 de junio de 2026
