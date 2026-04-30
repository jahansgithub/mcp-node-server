import { BigQuery } from "@google-cloud/bigquery";
import { promises as fs } from "fs";

export const DEFAULT_SENSITIVE_PATTERNS = [
  "%first_name%", "%last_name%", "%full_name%", "%fullname%",
  "%patient_name%", "%member_name%",
  "%email%", "%phone%", "%address%",
  "%zip_code%", "%zipcode%", "%postal_code%",
  "%ssn%", "%social_security%",
  "%date_of_birth%", "%dob%", "%birth_date%",
  "%mrn%", "%medical_record%",
  "%insurance_id%", "%member_id%", "%subscriber_id%", "%npi%",
  "%password%", "%token%", "%secret%",
  "%access_key%", "%api_key%", "%credential%",
];

// Validate pattern safety
const SAFE_PATTERN = /^[a-zA-Z0-9_%.\-]+$/;

function validatePatterns(patterns) {
  for (const p of patterns) {
    if (!SAFE_PATTERN.test(p)) {
      throw new Error(
        `Invalid sensitiveFieldPattern: "${p}". Allowed: letters, digits, %, _, ., -`
      );
    }
  }
}

// ---------------- SCAN ----------------

export async function scanSensitiveFields(
  bigquery,
  patterns,
  location = "US"
) {
  validatePatterns(patterns);

  const likeConditions = patterns
    .map((p) => `LOWER(column_name) LIKE '${p}'`)
    .join("\n   OR ");

  const sql = `
    FROM \`region-${location.toLowerCase()}\`.INFORMATION_SCHEMA.COLUMNS
    |> WHERE ${likeConditions}
    |> AGGREGATE ARRAY_AGG(column_name ORDER BY column_name) AS columns
       GROUP BY table_schema, table_name
    |> ORDER BY table_schema, table_name
  `;

  console.error("Scanning all datasets for sensitive fields...");

  const [rows] = await bigquery.query({ query: sql, location });

  const results = [];

  for (const row of rows) {
    for (const col of row.columns) {
      results.push({
        table_schema: row.table_schema,
        table_name: row.table_name,
        column_name: col,
      });
    }
  }

  console.error(
    `Found ${results.length} sensitive column(s) across ${rows.length} table(s)`
  );

  return results;
}

// ---------------- MERGE ----------------

export function mergeFields(existing, discovered) {
  const merged = { ...existing };

  for (const { table_schema, table_name, column_name } of discovered) {
    const tableKey = `${table_schema}.${table_name}`;

    if (!merged[tableKey]) {
      merged[tableKey] = [];
    }

    const exists = merged[tableKey].some(
      (c) => c.toLowerCase() === column_name.toLowerCase()
    );

    if (!exists) {
      merged[tableKey].push(column_name);
    }
  }

  const sorted = {};

  for (const key of Object.keys(merged).sort((a, b) =>
    a.toLowerCase().localeCompare(b.toLowerCase())
  )) {
    sorted[key] = merged[key].sort((a, b) =>
      a.toLowerCase().localeCompare(b.toLowerCase())
    );
  }

  return sorted;
}

// ---------------- STALE CHECK ----------------

function isStale(lastScannedAt, frequencyDays) {
  if (frequencyDays <= 0) return false;
  if (!lastScannedAt) return true;

  const elapsed = Date.now() - new Date(lastScannedAt).getTime();
  const limit = frequencyDays * 24 * 60 * 60 * 1000;

  return elapsed >= limit;
}

// ---------------- AUTO SCAN ----------------

export async function runDailyScanIfNeeded(
  bigquery,
  configPath,
  location = "US"
) {
  let existingConfig = {
    maximumBytesBilled: "10000000000",
    preventedFields: {},
  };

  try {
    const raw = await fs.readFile(configPath, "utf-8");
    existingConfig = JSON.parse(raw);
  } catch {
    // use default
  }

  const frequencyDays =
    typeof existingConfig.sensitiveFieldScanFrequencyDays === "number"
      ? existingConfig.sensitiveFieldScanFrequencyDays
      : 1;

  const patterns = Array.isArray(existingConfig.sensitiveFieldPatterns)
    ? existingConfig.sensitiveFieldPatterns
    : DEFAULT_SENSITIVE_PATTERNS;

  const existingPreventedFields = existingConfig.preventedFields || {};
  const lastScannedAt = existingConfig.lastScannedAt;

  if (!isStale(lastScannedAt, frequencyDays)) {
    console.error(
      `Config fresh (last scanned: ${lastScannedAt}), skipping scan`
    );
    return false;
  }

  console.error(
    lastScannedAt
      ? `Config stale (last scanned: ${lastScannedAt}), running scan...`
      : "First run — scanning sensitive fields..."
  );

  const discovered = await scanSensitiveFields(
    bigquery,
    patterns,
    location
  );

  const merged = mergeFields(existingPreventedFields, discovered);

  const updatedConfig = {
    ...existingConfig,
    preventedFields: merged,
    lastScannedAt: new Date().toISOString(),
  };

  await fs.writeFile(
    configPath,
    JSON.stringify(updatedConfig, null, 2) + "\n",
    "utf-8"
  );

  console.error(
    `Scan complete: ${Object.keys(merged).length} tables updated`
  );

  return true;
}