export const AGGREGATE_FUNCTIONS = ["count", "countif", "avg", "sum"];

export function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function buildTableAliasMap(sql) {
  const aliasMap = {};
  const tableRefPattern =
    /\b(?:from|join)\s+([a-z0-9_.\-]+)(?:\s+(?:as\s+)?([a-z0-9_]+))?/g;

  let match;

  while ((match = tableRefPattern.exec(sql)) !== null) {
    const [, tableName, alias] = match;
    if (alias) {
      aliasMap[alias] = tableName;
    }
  }

  return aliasMap;
}

export function referencesSameTable(candidate, expected) {
  if (candidate === expected) return true;
  if (candidate.endsWith(`.${expected}`)) return true;
  return expected.endsWith(`.${candidate}`);
}

export function extractSelectClause(sql) {
  const clauses = [];

  const standardMatch = sql.match(/\bselect\b([\s\S]*?)\bfrom\b/);
  if (standardMatch) {
    clauses.push(standardMatch[1]);
  }

  const pipeSelectPattern = /\|>\s*select\b([\s\S]*?)(?=\|>|;|$)/g;
  let match;

  while ((match = pipeSelectPattern.exec(sql)) !== null) {
    clauses.push(match[1]);
  }

  return clauses.join(" , ");
}

function parseExceptColumns(segment) {
  const full = new Set();
  const bare = new Set();

  segment
    .split(",")
    .map((v) => v.trim())
    .filter(Boolean)
    .forEach((value) => {
      const cleaned = value.replace(/`/g, "");
      const normalized = cleaned.toLowerCase();

      full.add(normalized);

      const bareName = normalized.split(".").pop();
      if (bareName) bare.add(bareName);
    });

  return { full, bare };
}

export function extractStarUsages(selectClause) {
  const usages = [];
  if (!selectClause) return usages;

  const starPattern =
    /(?:\b([a-z0-9_.\-]+)\.)?\*\s*(?:except\s*\(([^)]+)\))?/g;

  let match;

  while ((match = starPattern.exec(selectClause)) !== null) {
    const matchIndex = match.index ?? starPattern.lastIndex - match[0].length;
    const precedingIndex = matchIndex - 1;
    const charBefore = precedingIndex >= 0 ? selectClause[precedingIndex] : " ";

    if (charBefore === "(") continue;
    if (matchIndex > 0 && !/[,\s]/.test(charBefore)) continue;

    const qualifier = match[1]?.toLowerCase();
    const exceptSegment = match[2];

    const exceptColumns = new Set();
    const exceptBareColumns = new Set();

    if (exceptSegment) {
      const parsed = parseExceptColumns(exceptSegment);
      parsed.full.forEach((v) => exceptColumns.add(v));
      parsed.bare.forEach((v) => exceptBareColumns.add(v));
    }

    usages.push({ qualifier, exceptColumns, exceptBareColumns });
  }

  return usages;
}

export function starUsageCoversField(
  usage,
  field,
  tableName,
  aliasToTableMap
) {
  if (usage.exceptBareColumns.has(field)) return true;
  if (usage.exceptColumns.has(field)) return true;
  if (usage.exceptColumns.has(`${tableName}.${field}`)) return true;

  if (!usage.qualifier) return false;

  const qualifier = usage.qualifier;

  if (usage.exceptColumns.has(`${qualifier}.${field}`)) return true;

  const resolved = aliasToTableMap[qualifier];

  if (resolved) {
    if (usage.exceptColumns.has(`${resolved}.${field}`)) return true;
    if (
      usage.exceptBareColumns.has(field) &&
      referencesSameTable(resolved, tableName)
    ) {
      return true;
    }
  }

  return false;
}

export function stripCommentsAndLiterals(sql) {
  return sql
    .replace(/--[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/'(?:[^'\\]|\\.)*'/g, "''")
    .replace(/"(?:[^"\\]|\\.)*"/g, '""');
}

export function enforceFieldRestrictions(sql, restrictions) {
  if (!Object.keys(restrictions).length) return;

  const normalizedSql = stripCommentsAndLiterals(
    sql.replace(/`/g, "")
  ).toLowerCase();

  const blockedColumnsByTable = {};
  const aliasToTableMap = buildTableAliasMap(normalizedSql);
  const selectClause = extractSelectClause(normalizedSql);
  const starUsages = extractStarUsages(selectClause);

  for (const [tableName, restrictedFields] of Object.entries(restrictions)) {
    if (!normalizedSql.includes(tableName)) continue;

    const structAliasViolation = (() => {
      if (!selectClause.trim()) return false;

      for (const [alias, resolvedTable] of Object.entries(aliasToTableMap)) {
        if (!referencesSameTable(resolvedTable, tableName)) continue;

        const pattern = new RegExp(`\\b${escapeRegExp(alias)}\\b(?!\\.)`);
        if (pattern.test(selectClause)) return true;
      }

      const shortName = tableName.split(".").pop();
      const pattern = new RegExp(`\\b${escapeRegExp(shortName)}\\b(?!\\.)`);

      if (pattern.test(selectClause)) {
        const isTableRef =
          normalizedSql.includes(tableName) &&
          (aliasToTableMap[shortName] !== undefined ||
            new RegExp(
              `\\bfrom\\b[^]*\\b${escapeRegExp(shortName)}\\b`
            ).test(normalizedSql));

        if (isTableRef) return true;
      }

      return false;
    })();

    if (structAliasViolation) {
      blockedColumnsByTable[tableName] = new Set(restrictedFields);
      continue;
    }

    const relevantStarUsages = starUsages.filter((usage) => {
      if (!usage.qualifier) return true;

      const resolved = aliasToTableMap[usage.qualifier] ?? usage.qualifier;
      return referencesSameTable(resolved, tableName);
    });

    const hasNoSelectClause =
      !selectClause.trim() && !/\|>\s*aggregate\b/.test(normalizedSql);

    const starViolation = (() => {
      if (hasNoSelectClause) return true;

      if (!relevantStarUsages.length) return false;

      return relevantStarUsages.some((usage) => {
        if (!usage.exceptColumns.size && !usage.exceptBareColumns.size) {
          return true;
        }

        return restrictedFields.some(
          (f) => !starUsageCoversField(usage, f, tableName, aliasToTableMap)
        );
      });
    })();

    if (starViolation) {
      blockedColumnsByTable[tableName] = new Set(restrictedFields);
    }

    for (const field of restrictedFields) {
      const fieldPattern = new RegExp(`\\b${escapeRegExp(field)}\\b`);

      const aggregatePattern = new RegExp(
        `\\b(?:${AGGREGATE_FUNCTIONS.join("|")})\\s*\\([^)]*\\b${escapeRegExp(
          field
        )}\\b[^)]*\\)`,
        "g"
      );

      const cleaned = normalizedSql
        .replace(aggregatePattern, "")
        .replace(/\bexcept\s*\([^)]*\)/g, "");

      if (fieldPattern.test(cleaned)) {
        if (!blockedColumnsByTable[tableName]) {
          blockedColumnsByTable[tableName] = new Set();
        }
        blockedColumnsByTable[tableName].add(field);
      }
    }
  }

  if (Object.keys(blockedColumnsByTable).length) {
    const messageDetails = Object.entries(blockedColumnsByTable)
      .map(([table]) => {
        const cols = restrictions[table]
          .map((c) => `"${c}"`)
          .join(", ");
        return `table "${table}" has restricted columns: ${cols}`;
      })
      .join("; ");

    const allowedAgg = `[${AGGREGATE_FUNCTIONS.map(
      (f) => `"${f}"`
    ).join(", ")}]`;

    throw new Error(
      `Restricted fields detected — ${messageDetails}. You can only use these columns inside ${allowedAgg} or exclude via SELECT * EXCEPT (...).`
    );
  }
}

// ---------------- ALLOWED TABLES ----------------

function extractCteNames(sql) {
  const cteNames = new Set();

  let match;

  const withPattern = /\bwith\s+([a-z0-9_]+)\s+as\s*\(/g;
  while ((match = withPattern.exec(sql)) !== null) {
    cteNames.add(match[1]);
  }

  const commaPattern = /,\s*([a-z0-9_]+)\s+as\s*\(/g;
  while ((match = commaPattern.exec(sql)) !== null) {
    cteNames.add(match[1]);
  }

  return cteNames;
}

export function extractReferencedTables(sql) {
  const normalizedSql = stripCommentsAndLiterals(
    sql.replace(/`/g, "")
  ).toLowerCase();

  const cteNames = extractCteNames(normalizedSql);
  const tables = [];

  let match;

  const fromPattern =
    /\bfrom\s+((?:[a-z0-9_.\-]+(?:\s*,\s*[a-z0-9_.\-]+)*))/g;

  while ((match = fromPattern.exec(normalizedSql)) !== null) {
    for (const t of match[1].split(",")) {
      const name = t.trim().split(/\s/)[0];
      if (name) tables.push(name);
    }
  }

  const joinPattern = /\bjoin\s+([a-z0-9_.\-]+)/g;
  while ((match = joinPattern.exec(normalizedSql)) !== null) {
    tables.push(match[1]);
  }

  return [...new Set(tables)].filter((t) => !cteNames.has(t));
}

export function tableMatchesAllowedEntry(queried, allowed) {
  return referencesSameTable(queried, allowed);
}

export function enforceAllowedTables(sql, allowedTables) {
  if (!allowedTables.length) {
    throw new Error("No tables are configured as allowed.");
  }

  const normalizedAllowed = allowedTables.map((t) => t.toLowerCase());
  const referencedTables = extractReferencedTables(sql);

  if (
    referencedTables.length === 0 &&
    /\b(from|select)\b/.test(sql.toLowerCase())
  ) {
    throw new Error("Unable to determine referenced tables.");
  }

  const disallowed = referencedTables.filter(
    (t) =>
      !t.includes("information_schema") &&
      !normalizedAllowed.some((a) => tableMatchesAllowedEntry(t, a))
  );

  if (disallowed.length) {
    throw new Error(`Access denied: ${disallowed.join(", ")}`);
  }
}

export function validateIsSelectStatement(statementType) {
  if (statementType !== "SELECT") {
    throw new Error(
      `Only SELECT queries are allowed. This query was identified as: ${
        statementType ?? "UNKNOWN"
      }`
    );
  }
}