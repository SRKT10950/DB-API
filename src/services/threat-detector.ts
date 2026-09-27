export type OperationType = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE' | 'DDL' | 'UNKNOWN';
export type ThreatLevel = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ThreatAnalysisResult {
  isValid: boolean;
  operationType: OperationType;
  detectedOperations: OperationType[];
  threatLevel: ThreatLevel;
  threatReason: string | null;
  sanitizedSummary: string;
}

export class ThreatDetector {
  // Common SQL injection patterns
  private static SQLI_PATTERNS = [
    // Tautology / Boolean-based attacks
    {
      regex: /(?:'|\b)\s*(?:OR|AND)\s+['"]?[0-9a-zA-Z]+['"]?\s*=\s*['"]?[0-9a-zA-Z]+['"]?/i,
      reason: 'SQL Injection detected: Boolean tautology pattern',
      level: 'CRITICAL' as ThreatLevel,
    },
    {
      regex: /\bOR\s+1\s*=\s*1\b|\bOR\s+'1'\s*=\s*'1'\b|\bOR\s+true\b/i,
      reason: 'SQL Injection detected: Classic OR 1=1 bypass',
      level: 'CRITICAL' as ThreatLevel,
    },
    // UNION-based injection
    {
      regex: /\bUNION(?:\s+ALL)?\s+SELECT\b/i,
      reason: 'SQL Injection detected: Unauthorized UNION query',
      level: 'CRITICAL' as ThreatLevel,
    },
    // Time-based and denial of service attacks
    {
      regex: /\bpg_sleep\s*\(/i,
      reason: 'SQL Injection detected: Time-delay function pg_sleep()',
      level: 'CRITICAL' as ThreatLevel,
    },
    {
      regex: /\bpg_terminate_backend\s*\(/i,
      reason: 'Security violation: Attempt to terminate PostgreSQL processes',
      level: 'CRITICAL' as ThreatLevel,
    },
    // Unauthorized system schema probing
    {
      regex: /\bpg_shadow\b|\bpg_authid\b|\bpg_catalog\.pg_authid\b/i,
      reason: 'Security violation: Attempt to query PostgreSQL credential catalogs',
      level: 'CRITICAL' as ThreatLevel,
    },
    // Arbitrary shell / file access attempts
    {
      regex: /\bCOPY\s+.*\s+FROM\s+PROGRAM\b/i,
      reason: 'Remote Code Execution attempt: COPY FROM PROGRAM detected',
      level: 'CRITICAL' as ThreatLevel,
    },
    // Inline comment tricks hiding payloads
    {
      regex: /\/\*![\s\S]*?\*\/|;--|\badmin'--|\b' OR 1=1--/i,
      reason: 'SQL Injection detected: Obfuscated comment sequence',
      level: 'HIGH' as ThreatLevel,
    },
  ];

  // DDL keywords
  private static DDL_PATTERNS = [
    /\bCREATE\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA|FUNCTION|PROCEDURE|TRIGGER|EXTENSION|SEQUENCE)\b/i,
    /\bALTER\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA|FUNCTION|PROCEDURE|TRIGGER|SEQUENCE)\b/i,
    /\bDROP\s+(?:TABLE|DATABASE|INDEX|VIEW|SCHEMA|FUNCTION|PROCEDURE|TRIGGER|EXTENSION|SEQUENCE)\b/i,
    /\bTRUNCATE(?:\s+TABLE)?\b/i,
    /\bGRANT\s+.*\s+TO\b/i,
    /\bREVOKE\s+.*\s+FROM\b/i,
    /\bVACUUM\b/i,
    /\bREINDEX\b/i,
  ];

  /**
   * Analyzes an incoming SQL string and checks for threats and operations.
   */
  public static analyzeQuery(query: string): ThreatAnalysisResult {
    const trimmed = query.trim();
    if (!trimmed) {
      return {
        isValid: false,
        operationType: 'UNKNOWN',
        detectedOperations: [],
        threatLevel: 'LOW',
        threatReason: 'Empty query string provided',
        sanitizedSummary: '',
      };
    }

    const sanitizedSummary = trimmed.replace(/\s+/g, ' ').substring(0, 150);

    // 1. Check for SQL Injection patterns
    for (const pattern of this.SQLI_PATTERNS) {
      if (pattern.regex.test(trimmed)) {
        return {
          isValid: false,
          operationType: 'UNKNOWN',
          detectedOperations: [],
          threatLevel: pattern.level,
          threatReason: pattern.reason,
          sanitizedSummary,
        };
      }
    }

    // 2. Split statements (by semicolon, ignoring semicolons within quotes)
    const statements = this.splitSqlStatements(trimmed);
    const detectedOps: Set<OperationType> = new Set();

    for (const stmt of statements) {
      const op = this.detectStatementOperation(stmt);
      detectedOps.add(op);
    }

    const detectedOpsArray = Array.from(detectedOps);

    // Check if DDL is present in any statement
    const hasDDL = detectedOps.has('DDL');

    // Primary operation is DDL if any DDL exists, otherwise the first detected operation
    let primaryOp: OperationType = hasDDL ? 'DDL' : (detectedOpsArray[0] || 'UNKNOWN');

    // Check for stacked destructive queries
    if (statements.length > 1) {
      if (hasDDL) {
        return {
          isValid: true,
          operationType: 'DDL',
          detectedOperations: detectedOpsArray,
          threatLevel: 'MEDIUM',
          threatReason: 'Multi-statement execution containing DDL operations',
          sanitizedSummary,
        };
      }
    }

    return {
      isValid: true,
      operationType: primaryOp,
      detectedOperations: detectedOpsArray,
      threatLevel: 'NONE',
      threatReason: null,
      sanitizedSummary,
    };
  }

  /**
   * Identifies the primary operation of a single SQL statement.
   */
  private static detectStatementOperation(statement: string): OperationType {
    const clean = statement.trim();

    // Check DDL first
    for (const ddlRegex of this.DDL_PATTERNS) {
      if (ddlRegex.test(clean)) {
        return 'DDL';
      }
    }

    const firstWordMatch = clean.match(/^([a-zA-Z]+)/);
    if (!firstWordMatch) return 'UNKNOWN';

    const firstWord = firstWordMatch[1].toUpperCase();

    switch (firstWord) {
      case 'SELECT':
      case 'EXPLAIN':
      case 'SHOW':
      case 'WITH':
        // If WITH statement, check what it does (WITH ... SELECT vs WITH ... INSERT)
        if (firstWord === 'WITH') {
          if (/\bINSERT\s+INTO\b/i.test(clean)) return 'INSERT';
          if (/\bUPDATE\b/i.test(clean)) return 'UPDATE';
          if (/\bDELETE\s+FROM\b/i.test(clean)) return 'DELETE';
          return 'SELECT';
        }
        return 'SELECT';
      case 'INSERT':
        return 'INSERT';
      case 'UPDATE':
        return 'UPDATE';
      case 'DELETE':
        return 'DELETE';
      default:
        return 'UNKNOWN';
    }
  }

  /**
   * Splits SQL string into discrete statements without breaking inside strings.
   */
  private static splitSqlStatements(sql: string): string[] {
    const statements: string[] = [];
    let current = '';
    let inSingleQuote = false;
    let inDoubleQuote = false;
    let inDollarQuote = false;
    let dollarTag = '';

    for (let i = 0; i < sql.length; i++) {
      const char = sql[i];
      const nextChar = sql[i + 1] || '';

      if (char === "'" && !inDoubleQuote && !inDollarQuote) {
        if (inSingleQuote && nextChar === "'") {
          current += "''";
          i++;
          continue;
        }
        inSingleQuote = !inSingleQuote;
        current += char;
      } else if (char === '"' && !inSingleQuote && !inDollarQuote) {
        inDoubleQuote = !inDoubleQuote;
        current += char;
      } else if (char === '$' && !inSingleQuote && !inDoubleQuote) {
        // Simple dollar tag handling ($$, $tag$)
        const match = sql.substring(i).match(/^(\$[a-zA-Z0-9_]*\$)/);
        if (match) {
          const tag = match[1];
          if (!inDollarQuote) {
            inDollarQuote = true;
            dollarTag = tag;
          } else if (tag === dollarTag) {
            inDollarQuote = false;
            dollarTag = '';
          }
          current += tag;
          i += tag.length - 1;
        } else {
          current += char;
        }
      } else if (char === ';' && !inSingleQuote && !inDoubleQuote && !inDollarQuote) {
        if (current.trim().length > 0) {
          statements.push(current.trim());
        }
        current = '';
      } else {
        current += char;
      }
    }

    if (current.trim().length > 0) {
      statements.push(current.trim());
    }

    return statements;
  }
}
