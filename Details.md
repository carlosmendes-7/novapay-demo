# NovaPay DemoShop — F5 Distributed Cloud WAAP/WAF Demo v3

Aplicación web estática + APIs serverless para Vercel, pensada para demostraciones de F5 Distributed Cloud WAAP/WAF sobre el dominio:

```text
https://demoapi.f5latam.app
```

## Cambios principales de la v3

La funcionalidad **WAF Attack Lab** fue corregida para generar tráfico real hacia endpoints activos, no sólo hacia un endpoint genérico.

Ahora existen endpoints serverless reales bajo `/api/*`, manejados por `api/[...slug].js` y `api/_demo-handler.js`. Si F5 Distributed Cloud WAAP está delante del dominio, cada request llega primero al WAF. Si el WAF bloquea, el backend no responde. Si el WAF permite, la función responde `200 OK` con metadata demo.

## Endpoints activos

Estos endpoints son reales dentro del deployment Vercel:

```text
GET  /api/system/health
GET  /api/products/search
POST /api/auth/login
POST /api/cart/checkout
POST /api/users/profile
GET  /api/files/download
POST /api/files/download
GET  /api/reports/export
POST /api/reports/export
GET  /api/webhooks/register
POST /api/webhooks/register
GET  /api/admin/lookup
GET  /api/recon/probe
GET  /api/support/ticket
POST /api/support/ticket
GET  /api/waf-lab
POST /api/waf-lab
```

## Escenarios del WAF Attack Lab

| Escenario | Endpoints utilizados | Detección esperada |
|---|---|---|
| SQL Injection | `/api/products/search`, `/api/admin/lookup`, `/api/auth/login` | SQL Injection / Injection Attack |
| Cross-Site Scripting | `/api/products/search`, `/api/support/ticket`, `/api/users/profile` | XSS / Script Injection |
| Path Traversal / LFI | `/api/files/download`, `/api/reports/export` | Directory Traversal / Local File Inclusion |
| Command Injection | `/api/reports/export`, `/api/system/health` | OS Command Injection |
| SSRF / Metadata Probe | `/api/webhooks/register` | SSRF / Metadata Service Probe |
| Recon / Sensitive Path | `/api/recon/probe` | Scanner / Sensitive File or Path Access |
| API Abuse / Schema Drift | `/api/cart/checkout`, `/api/users/profile` | API schema violation / sensitive field exposure |

## Cómo validar

1. Desplegar el proyecto en Vercel.
2. Apuntar el dominio `demoapi.f5latam.app` al deployment.
3. Publicar el servicio detrás de F5 Distributed Cloud WAAP.
4. Abrir:

```text
https://demoapi.f5latam.app
```

5. Ir a **WAF Attack Lab**.
6. Presionar **Test Active APIs**.
   - Si responde `200`, los endpoints serverless están vivos.
   - Si responde `403`, `406` o `429`, F5 XC está bloqueando o interviniendo.
7. Marcar la confirmación de ejecución controlada.
8. Ejecutar un escenario individual, por ejemplo **SQL Injection**.
9. Revisar en F5 Distributed Cloud:
   - Security Events
   - WAAP Events
   - HTTP Load Balancer request logs
   - WAF violations/signatures

## Seguridad de la demo

Los payloads son datos inertes. El backend no ejecuta comandos, no abre callbacks, no lee archivos, no consulta base de datos y no autentica usuarios reales.

El objetivo es generar tráfico HTTP con firmas detectables para que F5 Distributed Cloud pueda bloquear o registrar los eventos sin afectar sistemas productivos.

## Límite de tráfico

La UI limita la ejecución a:

- Máximo 30 requests por corrida.
- Delay mínimo de 250 ms.
- Sin fuzzing infinito.
- Target no editable: `https://demoapi.f5latam.app`.

## Archivos principales

```text
index.html                 # SPA NovaPay + Traffic Generator + WAF Attack Lab
api/_demo-handler.js        # Handler común para APIs activas
api/[...slug].js            # Catch-all serverless para /api/*
api/waf-lab.js              # Endpoint legacy compatible
vercel.json                 # Rewrites SPA y headers no-store para APIs
```
