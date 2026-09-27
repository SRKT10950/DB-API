import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { metadataStore, ApiKeyRecord, DeviceRecord } from '../services/metadata-store';
import { KeyService } from '../services/key-service';

export interface SecurityContext {
  keyRecord: ApiKeyRecord;
  appName: string;
  dbName: string;
  deviceName: string;
  deviceType: string;
  location: string;
  reportedIp: string;
  actualIp: string;
  deviceRecord?: DeviceRecord;
  startTime: number;
}

// Extend Express Request
declare global {
  namespace Express {
    interface Request {
      securityContext?: SecurityContext;
    }
  }
}

export function securityHeadersMiddleware(req: Request, res: Response, next: NextFunction) {
  const startTime = performance.now();

  // Helper to extract case-insensitive header
  const getHeader = (names: string[]): string | undefined => {
    for (const name of names) {
      const val = req.headers[name.toLowerCase()];
      if (typeof val === 'string' && val.trim().length > 0) {
        return val.trim();
      }
    }
    return undefined;
  };

  const key = getHeader(['Key', 'x-api-key']);
  const ip = getHeader(['IP', 'x-client-ip']);
  const deviceName = getHeader(['DeviceName', 'x-device-name']);
  const location = getHeader(['Location', 'x-location']);
  const deviceType = getHeader(['DeviceType', 'x-device-type']);
  const appName = getHeader(['AppName', 'x-app-name']);
  const deviceSecurityKey = getHeader([
    'Device Security Key',
    'Device-Security-Key',
    'DeviceSecurityKey',
    'x-device-security-key',
  ]);

  // Actual IP from connection
  const actualIp =
    (req.headers['x-forwarded-for'] as string)?.split(',')[0].trim() ||
    req.socket.remoteAddress ||
    '127.0.0.1';

  const targetDbName = req.params.dbName || '';

  // 1. Verify all 7 required headers are present
  const missingHeaders: string[] = [];
  if (!key) missingHeaders.push('Key');
  if (!ip) missingHeaders.push('IP');
  if (!deviceName) missingHeaders.push('DeviceName');
  if (!location) missingHeaders.push('Location');
  if (!deviceType) missingHeaders.push('DeviceType');
  if (!appName) missingHeaders.push('AppName');
  if (!deviceSecurityKey) missingHeaders.push('Device Security Key');

  if (missingHeaders.length > 0) {
    metadataStore.addAuditLog({
      id: `log_${crypto.randomBytes(6).toString('hex')}`,
      timestamp: new Date().toISOString(),
      keyId: null,
      appName: appName || 'UNKNOWN',
      dbName: targetDbName || 'UNKNOWN',
      endpoint: req.originalUrl,
      method: req.method,
      deviceName: deviceName || 'UNKNOWN',
      deviceType: deviceType || 'UNKNOWN',
      location: location || 'UNKNOWN',
      reportedIp: ip || 'UNKNOWN',
      actualIp,
      operationType: 'AUTH_FAILED',
      querySummary: `Rejected: Missing required security headers (${missingHeaders.join(', ')})`,
      durationMs: Math.round(performance.now() - startTime),
      statusCode: 400,
      threatLevel: 'MEDIUM',
      threatReason: `Missing required security headers: ${missingHeaders.join(', ')}`,
      rowCount: null,
    });

    return res.status(400).json({
      success: false,
      error: 'Missing required security header(s)',
      requiredHeaders: [
        'Key',
        'IP',
        'DeviceName',
        'Location',
        'DeviceType',
        'AppName',
        'Device Security Key',
      ],
      missingHeaders,
    });
  }

  // 2. Validate API Key
  const keyHash = KeyService.hashKey(key!);
  const keyRecord = metadataStore.findKeyByHash(keyHash);

  if (!keyRecord || keyRecord.status !== 'active') {
    metadataStore.addAuditLog({
      id: `log_${crypto.randomBytes(6).toString('hex')}`,
      timestamp: new Date().toISOString(),
      keyId: null,
      appName: appName!,
      dbName: targetDbName,
      endpoint: req.originalUrl,
      method: req.method,
      deviceName: deviceName!,
      deviceType: deviceType!,
      location: location!,
      reportedIp: ip!,
      actualIp,
      operationType: 'AUTH_FAILED',
      querySummary: 'Rejected: Invalid or revoked API Key',
      durationMs: Math.round(performance.now() - startTime),
      statusCode: 401,
      threatLevel: 'HIGH',
      threatReason: 'Invalid or revoked API Key provided',
      rowCount: null,
    });

    return res.status(401).json({
      success: false,
      error: 'Unauthorized: Invalid or revoked API Key',
    });
  }

  // 3. Check expiration
  if (keyRecord.expiresAt && new Date(keyRecord.expiresAt).getTime() < Date.now()) {
    return res.status(401).json({
      success: false,
      error: 'Unauthorized: API Key has expired',
    });
  }

  // 4. Validate AppName matches
  if (keyRecord.appName.toLowerCase() !== appName!.toLowerCase()) {
    metadataStore.addAuditLog({
      id: `log_${crypto.randomBytes(6).toString('hex')}`,
      timestamp: new Date().toISOString(),
      keyId: keyRecord.id,
      appName: appName!,
      dbName: targetDbName,
      endpoint: req.originalUrl,
      method: req.method,
      deviceName: deviceName!,
      deviceType: deviceType!,
      location: location!,
      reportedIp: ip!,
      actualIp,
      operationType: 'AUTH_FAILED',
      querySummary: `Rejected: AppName mismatch (Expected: ${keyRecord.appName}, Provided: ${appName})`,
      durationMs: Math.round(performance.now() - startTime),
      statusCode: 403,
      threatLevel: 'HIGH',
      threatReason: 'AppName does not match registered API Key owner',
      rowCount: null,
    });

    return res.status(403).json({
      success: false,
      error: `Forbidden: AppName '${appName}' does not match registered API Key owner`,
    });
  }

  // 5. Validate Database match (if path contains targetDbName)
  if (targetDbName && keyRecord.dbName.toLowerCase() !== targetDbName.toLowerCase()) {
    metadataStore.addAuditLog({
      id: `log_${crypto.randomBytes(6).toString('hex')}`,
      timestamp: new Date().toISOString(),
      keyId: keyRecord.id,
      appName: appName!,
      dbName: targetDbName,
      endpoint: req.originalUrl,
      method: req.method,
      deviceName: deviceName!,
      deviceType: deviceType!,
      location: location!,
      reportedIp: ip!,
      actualIp,
      operationType: 'AUTH_FAILED',
      querySummary: `Rejected: Database mismatch (Key authorized for: ${keyRecord.dbName}, Requested: ${targetDbName})`,
      durationMs: Math.round(performance.now() - startTime),
      statusCode: 403,
      threatLevel: 'HIGH',
      threatReason: 'Attempt to access unauthorized database using foreign API Key',
      rowCount: null,
    });

    return res.status(403).json({
      success: false,
      error: `Forbidden: API Key is not authorized to access database '${targetDbName}'`,
    });
  }

  // 6. Validate Device & Device Security Key
  const devKeyHash = KeyService.hashKey(deviceSecurityKey!);
  let deviceRecord = metadataStore.findDevice(appName!, deviceName!, deviceType!);

  if (deviceRecord) {
    if (deviceRecord.securityKeyHash !== devKeyHash) {
      metadataStore.addAuditLog({
        id: `log_${crypto.randomBytes(6).toString('hex')}`,
        timestamp: new Date().toISOString(),
        keyId: keyRecord.id,
        appName: appName!,
        dbName: targetDbName,
        endpoint: req.originalUrl,
        method: req.method,
        deviceName: deviceName!,
        deviceType: deviceType!,
        location: location!,
        reportedIp: ip!,
        actualIp,
        operationType: 'AUTH_FAILED',
        querySummary: `Rejected: Device Security Key mismatch for device '${deviceName}'`,
        durationMs: Math.round(performance.now() - startTime),
        statusCode: 401,
        threatLevel: 'CRITICAL',
        threatReason: 'Device Security Key mismatch (Potential device impersonation)',
        rowCount: null,
      });

      return res.status(401).json({
        success: false,
        error: 'Unauthorized: Invalid Device Security Key for specified Device',
      });
    }

    // Update last seen
    deviceRecord.lastSeenAt = new Date().toISOString();
  } else {
    // Auto-register first time device is verified with its security key
    const regResult = KeyService.registerDevice({
      appName: appName!,
      deviceName: deviceName!,
      deviceType: deviceType!,
    });
    // Replace hash with caller's hash
    regResult.deviceRecord.securityKeyHash = devKeyHash;
    regResult.deviceRecord.securityKeyPrefix = deviceSecurityKey!.substring(0, 10) + '...';
    metadataStore.saveDevice(regResult.deviceRecord);
    deviceRecord = regResult.deviceRecord;
  }

  // 7. Check IP Whitelist if configured on key
  if (keyRecord.allowedIps && keyRecord.allowedIps.length > 0) {
    const isWhitelisted =
      keyRecord.allowedIps.includes(ip!) || keyRecord.allowedIps.includes(actualIp);
    if (!isWhitelisted) {
      metadataStore.addAuditLog({
        id: `log_${crypto.randomBytes(6).toString('hex')}`,
        timestamp: new Date().toISOString(),
        keyId: keyRecord.id,
        appName: appName!,
        dbName: targetDbName,
        endpoint: req.originalUrl,
        method: req.method,
        deviceName: deviceName!,
        deviceType: deviceType!,
        location: location!,
        reportedIp: ip!,
        actualIp,
        operationType: 'AUTH_FAILED',
        querySummary: `Rejected: IP '${actualIp}' / '${ip}' is not in allowed IP whitelist`,
        durationMs: Math.round(performance.now() - startTime),
        statusCode: 403,
        threatLevel: 'HIGH',
        threatReason: 'Client IP address is not permitted by API Key whitelist',
        rowCount: null,
      });

      return res.status(403).json({
        success: false,
        error: 'Forbidden: IP address not allowed for this API Key',
      });
    }
  }

  // Update last used timestamp on key
  keyRecord.lastUsedAt = new Date().toISOString();
  metadataStore.scheduleSave();

  // Attach context
  req.securityContext = {
    keyRecord,
    appName: appName!,
    dbName: targetDbName,
    deviceName: deviceName!,
    deviceType: deviceType!,
    location: location!,
    reportedIp: ip!,
    actualIp,
    deviceRecord,
    startTime,
  };

  next();
}
