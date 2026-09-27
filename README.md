# DB API - PostgreSQL Database Gateway & Security Firewall

[![Platform: Docker APP](https://img.shields.io/badge/Platform-Docker%20App-blue.svg)](https://www.docker.com/)
[![Node: v20+](https://img.shields.io/badge/Node-v20%2B-green.svg)](https://nodejs.org/)
[![Database: PostgreSQL 16](https://img.shields.io/badge/Database-PostgreSQL%2016-336791.svg)](https://www.postgresql.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-purple.svg)](LICENSE)

A high-performance, secure Dockerized API Gateway designed to:
- **Expose local PostgreSQL databases via secure REST & SQL APIs** (`https://db.mhservice.co.in/API/1/:dbName`).
- **Protect local PostgreSQL from direct WAN exposure and thread exhaustion / DDoS**. The database port (5432) remains hidden inside an internal isolated network.
- **Enforce strict 7-point client security headers** before any request reaches the database.
- **Grant granular access control** per App and per Database (enabling/disabling `Create`, `Read`, `Update`, `Delete`, and `DDL`).
- **Detect and neutralize threats** (SQL injection, unauthorized DDL drop attacks, device spoofing, process termination attempts).
- **Monitor and audit every query** with duration, client metadata, threat scores, and a built-in real-time Web Admin Dashboard.

---

## 📑 Table of Contents
1. [Security Architecture](#security-architecture)
2. [7-Point Required Security Headers](#7-point-required-security-headers)
3. [Granular Access Control (CRUD & DDL)](#granular-access-control-crud--ddl)
4. [SQL Threat & Injection Defense](#sql-threat--injection-defense)
5. [API Endpoints Reference](#api-endpoints-reference)
6. [Quick Start & Docker Deployment](#quick-start--docker-deployment)
7. [PostgreSQL Setup & Environment Provisioning](#postgresql-setup--environment-provisioning)
8. [Web Admin Dashboard (`/admin`)](#web-admin-dashboard-admin)
9. [Running Automated Tests](#running-automated-tests)

---

## Security Architecture

```
                       INTERNET / WAN CLIENTS
                                 │
           [ HTTPS / REST API to db.mhservice.co.in ]
           Headers: Key, IP, DeviceName, Location,
                    DeviceType, AppName, Device-Security-Key
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────┐
│                 DB API Gateway (Docker Container)           │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ 1. 7-Point Security Header Validator                  │  │
│  │    • Verifies all 7 required headers                  │  │
│  │    • Validates Key, AppName, Device & Security Key    │  │
│  │    • Rate limiting & IP cross-verification            │  │
│  └───────────────────────────┬───────────────────────────┘  │
│                              │                              │
│  ┌───────────────────────────▼───────────────────────────┐  │
│  │ 2. SQL Firewall & Permission Engine                   │  │
│  │    • AST & regex threat heuristic inspection          │  │
│  │    • Enforces App Permissions:                        │  │
│  │      - CREATE (Insert)                                │  │
│  │      - READ (Select)                                  │  │
│  │      - UPDATE                                         │  │
│  │      - DELETE                                         │  │
│  │      - DDL (CREATE/ALTER/DROP TABLE, etc.)            │  │
│  │    • Blocks SQLi, UNION bypasses, and DROP attacks    │  │
│  └───────────────────────────┬───────────────────────────┘  │
│                              │                              │
│  ┌───────────────────────────▼───────────────────────────┐  │
│  │ 3. Multi-Tenant PostgreSQL Connection Pool            │  │
│  │    • Routes requests to target /API/1/:dbName         │  │
│  │    • Parameterized query execution ($1, $2, ...)      │  │
│  │    • Statement timeout defense (prevents hung queries)│  │
│  └───────────────────────────┬───────────────────────────┘  │
│                              │                              │
│  ┌───────────────────────────┴───────────────────────────┐  │
│  │ 4. Audit Engine & Real-Time Monitoring Dashboard      │  │
│  │    • Logs client IP, device, duration, query summary  │  │
│  │    • Interactive UI at /admin                         │  │
│  │    • Prometheus metrics at /metrics                   │  │
│  └───────────────────────────────────────────────────────┘  │
└──────────────────────────────┬──────────────────────────────┘
                               │
               Internal Docker Network (db-internal)
               Port 5432 (Never exposed to public WAN)
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                  PostgreSQL Database Engine                 │
│              (Protected Local PostgreSQL Instance)          │
└─────────────────────────────────────────────────────────────┘
```

---

## 7-Point Required Security Headers

Every request to `/API/1/:dbName` **must** provide the following 7 headers. If any header is missing or mismatched, the request is rejected immediately before reaching the database:

| Header Name | Type | Description | Security Check |
|---|---|---|---|
| `Key` | `string` | API Key generated for the App + Database (`dbapi_live_...`) | SHA-256 hashed lookup. Checks active status, expiry, and permissions. |
| `IP` | `string` | Client reported IP address | Cross-checked with socket IP / forward proxy. Validated against IP whitelist if configured. |
| `DeviceName` | `string` | Unique client machine identifier (e.g., `POS-Terminal-01`) | Validates machine bound to application profile. |
| `Location` | `string` | Physical location or branch tag (e.g., `HQ-Branch-1`) | Recorded in immutable audit log for forensics. |
| `DeviceType` | `string` | Device category: `Server`, `Desktop`, `Mobile`, `IoT` | Prevents unauthorized device escalation. |
| `AppName` | `string` | Registered application name (e.g., `StoreFrontApp`) | Must match the application registered to the API Key. |
| `Device Security Key` / `Device-Security-Key` | `string` | Cryptographic pre-shared secret for the device (`dsk_...`) | Prevents leaked API keys from being used on rogue or cloned devices. |

---

## Granular Access Control (CRUD & DDL)

Each API Key is bound to a specific application and database with independently configurable permissions:

- **`can_create` (Create / INSERT)**: Allows `INSERT` statements and RESTful `POST` records.
- **`can_read` (Read / SELECT)**: Allows `SELECT`, `EXPLAIN`, and RESTful `GET` queries.
- **`can_update` (Update / UPDATE)**: Allows `UPDATE` statements and RESTful `PUT`/`PATCH` operations.
- **`can_delete` (Delete / DELETE)**: Allows `DELETE` statements and RESTful `DELETE` operations.
- **`can_ddl` (DDL / Schema Changes)**: Allows `CREATE TABLE`, `ALTER TABLE`, `DROP TABLE`, `TRUNCATE`, `CREATE INDEX`.

> [!IMPORTANT]
> By default, standard application keys have **DDL disabled** (`can_ddl = false`). Any accidental or malicious `DROP TABLE` or `ALTER TABLE` statement attempted by the client is instantly blocked by the gateway firewall with HTTP 403 Forbidden and flagged in the threat log.

---

## SQL Threat & Injection Defense

The built-in **ThreatDetector** engine inspects all incoming SQL queries before execution:
1. **Tautology / Boolean-based SQL Injection**: Blocks patterns like `' OR '1'='1'`, `1=1--`, `or true`.
2. **UNION-based Attacks**: Blocks unauthorized `UNION SELECT` attempts.
3. **Stacked Malicious Commands**: Detects multi-statement injection trying to hide `DROP TABLE` or `TRUNCATE` behind a benign `SELECT`.
4. **Denial of Service / Process Injection**: Blocks `pg_sleep()`, `pg_terminate_backend()`.
5. **Credential Stealing**: Blocks queries targeting PostgreSQL internal catalogs (`pg_shadow`, `pg_authid`).
6. **Remote Code Execution**: Blocks `COPY ... FROM PROGRAM`.

---

## API Endpoints Reference

Base URL: `https://db.mhservice.co.in/API/1/:dbName`

### 1. Execute SQL Query
- **`POST /API/1/:dbName/query`**
- **Description**: Executes parameterized SQL queries with full threat analysis and permission verification.
- **Request Body**:
  ```json
  {
    "query": "SELECT id, name, price, stock_quantity FROM products WHERE status = $1 LIMIT $2;",
    "params": ["in_stock", 10]
  }
  ```
- **Response (200 OK)**:
  ```json
  {
    "success": true,
    "command": "SELECT",
    "rowCount": 2,
    "durationMs": 4.12,
    "rows": [
      {
        "id": 1,
        "name": "Wireless Noise Canceling Headphones",
        "price": "199.99",
        "stock_quantity": 45
      }
    ]
  }
  ```

### 2. List Tables
- **`GET /API/1/:dbName/tables`**
- **Requires**: `can_read: true`
- **Response**:
  ```json
  {
    "success": true,
    "count": 2,
    "tables": ["orders", "products"]
  }
  ```

### 3. RESTful Table Operations
- **`GET /API/1/:dbName/tables/:tableName`**:
  - Parameters: `?_limit=20&_offset=0&_sort=created_at&_order=desc&status=in_stock`
- **`POST /API/1/:dbName/tables/:tableName`**:
  - Body: `{ "sku": "SKU-99", "name": "Item Name", "price": 49.99 }`
- **`PUT / PATCH /API/1/:dbName/tables/:tableName?id=1`**:
  - Body: `{ "price": 39.99 }`
- **`DELETE /API/1/:dbName/tables/:tableName?id=1`**:
  - Requires: `can_delete: true`

### 4. DDL Schema Endpoint
- **`POST /API/1/:dbName/ddl`**
- **Requires**: `can_ddl: true`
- **Request Body**: `{ "sql": "CREATE TABLE inventory_audit (id SERIAL PRIMARY KEY, note TEXT);" }`

---

## Quick Start & Docker Deployment

### 1. Configure Environment
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

### 2. Start using Docker Compose
```bash
docker compose up -d --build
```
This starts:
1. `postgres`: PostgreSQL 16 (internal network only, protected from WAN).
2. `db-api`: DB API Gateway exposed on port 3000.

### 3. Verify Health
```bash
curl http://localhost:3000/health
```

---

## PostgreSQL Setup & Environment Provisioning

The DB API includes multiple automated options to configure PostgreSQL:

### Option A: One-Click Web Dashboard Provisioning
1. Open the Admin Dashboard: `http://localhost:3000/admin`.
2. Click **"Provision Demo DB & Test Keys"**.
3. It automatically creates `mh_demo_db`, generates sample tables (`products`, `orders`), seeds initial data, and generates a pre-configured API Key and Device Security Key.

### Option B: Automated CLI Setup Script
```bash
npm run setup:db
```
This script connects to PostgreSQL, creates the database, configures sample tables, registers demo applications, and prints ready-to-run `curl` commands.

---

## Web Admin Dashboard (`/admin`)

Access the interactive web console at:
`http://localhost:3000/admin`

Features:
- **Real-Time Overview**: Live traffic volume, blocked threats counter, PostgreSQL connection health, memory and uptime.
- **Key Manager**: Generate separate keys per App and Database with granular toggles for Create, Read, Update, Delete, and DDL permissions.
- **Device Security**: Register machine names and generate Device Security Keys.
- **Audit & Threat Logs**: Real-time log table showing client IP, device, latency, query summary, and color-coded threat alerts (`CRITICAL`, `HIGH`, `MEDIUM`).
- **Database Provisioner**: View databases and provision new databases directly.
- **Interactive API Playground**: Test queries with custom or pre-filled headers and see execution duration and response bodies.

---

## Running Automated Tests

Run the full end-to-end integration and security test suite:
```bash
npm run test:client
```

Tests include:
- Tautology SQL Injection defense (`OR 1=1`)
- Denial of service attack detection (`pg_sleep()`)
- DDL classification and blocked DDL enforcement
- 7-Point security headers verification (rejects missing headers)
- AppName mismatch defense (HTTP 403)
- Device Security Key mismatch defense (HTTP 401)
- Health check endpoints
