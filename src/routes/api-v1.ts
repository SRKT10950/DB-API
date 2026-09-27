import { Router, Request, Response } from 'express';
import crypto from 'crypto';
import { securityHeadersMiddleware, SecurityContext } from '../middleware/security-headers';
import { ThreatDetector } from '../services/threat-detector';
import { KeyService } from '../services/key-service';
import { PgPoolManager } from '../services/pg-pool';
import { metadataStore, AuditLogRecord } from '../services/metadata-store';

const router = Router({ mergeParams: true });

// Apply the 7-point header verification on all /API/1/:dbName routes
router.use(securityHeadersMiddleware);

/**
 * Helper to log audit records
 */
function recordAudit(
  ctx: SecurityContext,
  req: Request,
  operationType: AuditLogRecord['operationType'],
  querySummary: string,
  statusCode: number,
  threatLevel: AuditLogRecord['threatLevel'],
  threatReason: string | null,
  rowCount: number | null
) {
  const durationMs = Math.round((performance.now() - ctx.startTime) * 100) / 100;
  metadataStore.addAuditLog({
    id: `log_${crypto.randomBytes(6).toString('hex')}`,
    timestamp: new Date().toISOString(),
    keyId: ctx.keyRecord.id,
    appName: ctx.appName,
    dbName: ctx.dbName,
    endpoint: req.originalUrl,
    method: req.method,
    deviceName: ctx.deviceName,
    deviceType: ctx.deviceType,
    location: ctx.location,
    reportedIp: ctx.reportedIp,
    actualIp: ctx.actualIp,
    operationType,
    querySummary,
    durationMs,
    statusCode,
    threatLevel,
    threatReason,
    rowCount,
  });
}

/**
 * 1. POST /API/1/:dbName/query
 * Execute arbitrary parameterized SQL queries with threat detection & permission enforcement
 */
router.post('/query', async (req: Request, res: Response) => {
  const ctx = req.securityContext!;
  const { query, params } = req.body;

  if (!query || typeof query !== 'string') {
    return res.status(400).json({
      success: false,
      error: 'Invalid request body: "query" string is required',
    });
  }

  // 1. Analyze Query through Threat Detector
  const analysis = ThreatDetector.analyzeQuery(query);

  if (!analysis.isValid) {
    recordAudit(
      ctx,
      req,
      'BLOCKED',
      analysis.sanitizedSummary,
      403,
      analysis.threatLevel,
      analysis.threatReason,
      null
    );

    return res.status(403).json({
      success: false,
      error: 'Query blocked by Database Security Firewall',
      reason: analysis.threatReason,
      threatLevel: analysis.threatLevel,
    });
  }

  // 2. Check Permissions for all detected operations in the query
  for (const op of analysis.detectedOperations) {
    const permCheck = KeyService.checkPermission(ctx.keyRecord, op);
    if (!permCheck.allowed) {
      recordAudit(
        ctx,
        req,
        'BLOCKED',
        analysis.sanitizedSummary,
        403,
        'MEDIUM',
        `Permission denied: ${permCheck.reason}`,
        null
      );

      return res.status(403).json({
        success: false,
        error: 'Permission Denied',
        reason: permCheck.reason,
        operation: op,
        grantedPermissions: ctx.keyRecord.permissions,
      });
    }
  }

  // 3. Execute query on PostgreSQL
  try {
    const queryParams = Array.isArray(params) ? params : [];
    const result = await PgPoolManager.executeQuery(ctx.dbName, query, queryParams);

    recordAudit(
      ctx,
      req,
      analysis.operationType,
      analysis.sanitizedSummary,
      200,
      'NONE',
      null,
      result.rowCount
    );

    return res.status(200).json({
      success: true,
      command: result.command,
      rowCount: result.rowCount,
      durationMs: result.durationMs,
      rows: result.rows,
    });
  } catch (err: any) {
    const isConnErr = err.code === 'ECONNREFUSED' || err.code === '3D000';
    const statusCode = isConnErr ? 503 : 400;

    recordAudit(
      ctx,
      req,
      analysis.operationType,
      analysis.sanitizedSummary,
      statusCode,
      'LOW',
      err.message,
      null
    );

    return res.status(statusCode).json({
      success: false,
      error: err.message || 'Database query execution failed',
      code: err.code,
      hint: err.hint,
    });
  }
});

/**
 * 2. GET /API/1/:dbName/tables
 * Lists available tables
 */
router.get('/tables', async (req: Request, res: Response) => {
  const ctx = req.securityContext!;

  const perm = KeyService.checkPermission(ctx.keyRecord, 'SELECT');
  if (!perm.allowed) {
    return res.status(403).json({ success: false, error: perm.reason });
  }

  try {
    const tables = await PgPoolManager.listTables(ctx.dbName);
    recordAudit(ctx, req, 'SELECT', 'LIST TABLES', 200, 'NONE', null, tables.length);
    return res.json({ success: true, count: tables.length, tables });
  } catch (err: any) {
    return res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * 3. GET /API/1/:dbName/tables/:tableName
 * RESTful Query on a specific table
 */
router.get('/tables/:tableName', async (req: Request, res: Response) => {
  const ctx = req.securityContext!;
  const tableName = req.params.tableName;

  if (!/^[a-zA-Z0-9_]+$/.test(tableName)) {
    return res.status(400).json({ success: false, error: 'Invalid table name' });
  }

  const perm = KeyService.checkPermission(ctx.keyRecord, 'SELECT');
  if (!perm.allowed) {
    return res.status(403).json({ success: false, error: perm.reason });
  }

  const limit = Math.min(Math.max(parseInt((req.query._limit as string) || '50', 10), 1), 1000);
  const offset = Math.max(parseInt((req.query._offset as string) || '0', 10), 0);
  const sortCol = (req.query._sort as string) || '';
  const sortOrder = (req.query._order as string)?.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

  const filterClauses: string[] = [];
  const filterParams: any[] = [];
  let paramIdx = 1;

  for (const [key, val] of Object.entries(req.query)) {
    if (key.startsWith('_')) continue;
    if (!/^[a-zA-Z0-9_]+$/.test(key)) continue;

    filterClauses.push(`"${key}" = $${paramIdx++}`);
    filterParams.push(val);
  }

  const whereSql = filterClauses.length > 0 ? `WHERE ${filterClauses.join(' AND ')}` : '';
  const orderSql =
    sortCol && /^[a-zA-Z0-9_]+$/.test(sortCol) ? `ORDER BY "${sortCol}" ${sortOrder}` : '';

  const sql = `SELECT * FROM "${tableName}" ${whereSql} ${orderSql} LIMIT $${paramIdx++} OFFSET $${paramIdx++}`;
  filterParams.push(limit, offset);

  try {
    const result = await PgPoolManager.executeQuery(ctx.dbName, sql, filterParams);
    recordAudit(ctx, req, 'SELECT', `SELECT * FROM "${tableName}"`, 200, 'NONE', null, result.rowCount);

    return res.json({
      success: true,
      table: tableName,
      count: result.rowCount,
      limit,
      offset,
      data: result.rows,
    });
  } catch (err: any) {
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * 4. POST /API/1/:dbName/tables/:tableName
 * RESTful Insert records
 */
router.post('/tables/:tableName', async (req: Request, res: Response) => {
  const ctx = req.securityContext!;
  const tableName = req.params.tableName;

  if (!/^[a-zA-Z0-9_]+$/.test(tableName)) {
    return res.status(400).json({ success: false, error: 'Invalid table name' });
  }

  const perm = KeyService.checkPermission(ctx.keyRecord, 'INSERT');
  if (!perm.allowed) {
    return res.status(403).json({ success: false, error: perm.reason });
  }

  const payload = req.body;
  const items = Array.isArray(payload) ? payload : [payload];

  if (items.length === 0 || typeof items[0] !== 'object' || items[0] === null) {
    return res.status(400).json({ success: false, error: 'Request body must contain an object or array of objects' });
  }

  const columns = Object.keys(items[0]).filter((c) => /^[a-zA-Z0-9_]+$/.test(c));
  if (columns.length === 0) {
    return res.status(400).json({ success: false, error: 'No valid columns provided in request body' });
  }

  const colNames = columns.map((c) => `"${c}"`).join(', ');
  const valuesPlaceholders: string[] = [];
  const flatParams: any[] = [];
  let paramIdx = 1;

  for (const item of items) {
    const rowPlaceholders: string[] = [];
    for (const col of columns) {
      rowPlaceholders.push(`$${paramIdx++}`);
      flatParams.push(item[col] !== undefined ? item[col] : null);
    }
    valuesPlaceholders.push(`(${rowPlaceholders.join(', ')})`);
  }

  const sql = `INSERT INTO "${tableName}" (${colNames}) VALUES ${valuesPlaceholders.join(', ')} RETURNING *;`;

  try {
    const result = await PgPoolManager.executeQuery(ctx.dbName, sql, flatParams);
    recordAudit(ctx, req, 'INSERT', `INSERT INTO "${tableName}"`, 201, 'NONE', null, result.rowCount);

    return res.status(201).json({
      success: true,
      insertedCount: result.rowCount,
      data: result.rows,
    });
  } catch (err: any) {
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * 5. PUT / PATCH /API/1/:dbName/tables/:tableName
 * RESTful Update records matching query filter
 */
router.put('/tables/:tableName', handleUpdate);
router.patch('/tables/:tableName', handleUpdate);

async function handleUpdate(req: Request, res: Response) {
  const ctx = req.securityContext!;
  const tableName = req.params.tableName;

  if (!/^[a-zA-Z0-9_]+$/.test(tableName)) {
    return res.status(400).json({ success: false, error: 'Invalid table name' });
  }

  const perm = KeyService.checkPermission(ctx.keyRecord, 'UPDATE');
  if (!perm.allowed) {
    return res.status(403).json({ success: false, error: perm.reason });
  }

  const updateFields = req.body;
  if (!updateFields || typeof updateFields !== 'object' || Array.isArray(updateFields)) {
    return res.status(400).json({ success: false, error: 'Request body must be an object with fields to update' });
  }

  const setClauses: string[] = [];
  const params: any[] = [];
  let paramIdx = 1;

  for (const [col, val] of Object.entries(updateFields)) {
    if (!/^[a-zA-Z0-9_]+$/.test(col)) continue;
    setClauses.push(`"${col}" = $${paramIdx++}`);
    params.push(val);
  }

  if (setClauses.length === 0) {
    return res.status(400).json({ success: false, error: 'No valid columns provided to update' });
  }

  // Filters from query string
  const whereClauses: string[] = [];
  for (const [key, val] of Object.entries(req.query)) {
    if (key.startsWith('_')) continue;
    if (!/^[a-zA-Z0-9_]+$/.test(key)) continue;
    whereClauses.push(`"${key}" = $${paramIdx++}`);
    params.push(val);
  }

  if (whereClauses.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Safety restriction: UPDATE requires at least one query parameter filter (e.g. ?id=1)',
    });
  }

  const sql = `UPDATE "${tableName}" SET ${setClauses.join(', ')} WHERE ${whereClauses.join(' AND ')} RETURNING *;`;

  try {
    const result = await PgPoolManager.executeQuery(ctx.dbName, sql, params);
    recordAudit(ctx, req, 'UPDATE', `UPDATE "${tableName}"`, 200, 'NONE', null, result.rowCount);

    return res.json({
      success: true,
      updatedCount: result.rowCount,
      data: result.rows,
    });
  } catch (err: any) {
    return res.status(400).json({ success: false, error: err.message });
  }
}

/**
 * 6. DELETE /API/1/:dbName/tables/:tableName
 * RESTful Delete records matching query filter
 */
router.delete('/tables/:tableName', async (req: Request, res: Response) => {
  const ctx = req.securityContext!;
  const tableName = req.params.tableName;

  if (!/^[a-zA-Z0-9_]+$/.test(tableName)) {
    return res.status(400).json({ success: false, error: 'Invalid table name' });
  }

  const perm = KeyService.checkPermission(ctx.keyRecord, 'DELETE');
  if (!perm.allowed) {
    return res.status(403).json({ success: false, error: perm.reason });
  }

  const whereClauses: string[] = [];
  const params: any[] = [];
  let paramIdx = 1;

  for (const [key, val] of Object.entries(req.query)) {
    if (key.startsWith('_')) continue;
    if (!/^[a-zA-Z0-9_]+$/.test(key)) continue;
    whereClauses.push(`"${key}" = $${paramIdx++}`);
    params.push(val);
  }

  if (whereClauses.length === 0) {
    return res.status(400).json({
      success: false,
      error: 'Safety restriction: DELETE requires at least one query parameter filter (e.g. ?id=1)',
    });
  }

  const sql = `DELETE FROM "${tableName}" WHERE ${whereClauses.join(' AND ')} RETURNING *;`;

  try {
    const result = await PgPoolManager.executeQuery(ctx.dbName, sql, params);
    recordAudit(ctx, req, 'DELETE', `DELETE FROM "${tableName}"`, 200, 'NONE', null, result.rowCount);

    return res.json({
      success: true,
      deletedCount: result.rowCount,
      data: result.rows,
    });
  } catch (err: any) {
    return res.status(400).json({ success: false, error: err.message });
  }
});

/**
 * 7. POST /API/1/:dbName/ddl
 * Schema definition endpoint (CREATE TABLE, ALTER TABLE, DROP TABLE)
 */
router.post('/ddl', async (req: Request, res: Response) => {
  const ctx = req.securityContext!;
  const { sql } = req.body;

  if (!sql || typeof sql !== 'string') {
    return res.status(400).json({ success: false, error: 'Invalid request: "sql" string is required' });
  }

  const perm = KeyService.checkPermission(ctx.keyRecord, 'DDL');
  if (!perm.allowed) {
    recordAudit(ctx, req, 'BLOCKED', sql, 403, 'MEDIUM', 'DDL permission disabled', null);
    return res.status(403).json({ success: false, error: perm.reason });
  }

  const analysis = ThreatDetector.analyzeQuery(sql);
  if (!analysis.isValid) {
    recordAudit(ctx, req, 'BLOCKED', sql, 403, analysis.threatLevel, analysis.threatReason, null);
    return res.status(403).json({ success: false, error: analysis.threatReason });
  }

  try {
    const result = await PgPoolManager.executeQuery(ctx.dbName, sql);
    recordAudit(ctx, req, 'DDL', sql, 200, 'NONE', null, result.rowCount);

    return res.json({
      success: true,
      message: 'DDL command executed successfully',
      command: result.command,
      durationMs: result.durationMs,
    });
  } catch (err: any) {
    return res.status(400).json({ success: false, error: err.message });
  }
});

export default router;
