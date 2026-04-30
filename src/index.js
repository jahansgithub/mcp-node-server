#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { BigQuery } from "@google-cloud/bigquery";

import { promises as fs, constants as fsConstants } from "fs";
import path from "path";
import { runDailyScanIfNeeded } from "./sensitive-field-scanner.js";
import {
  enforceFieldRestrictions,
  enforceAllowedTables,
  validateIsSelectStatement,
} from "./sql-enforcement.js";

let config;
let bigquery;
let resourceBaseUrl;

let bigqueryConfig;
let configError = null;

// ---------------- CONFIG VALIDATION ----------------

async function validateConfig(config) {
  if (config.keyFilename) {
    const resolvedKeyPath = path.resolve(config.keyFilename);
    try {
      await fs.access(resolvedKeyPath, fsConstants.R_OK);
      config.keyFilename = resolvedKeyPath;
    } catch (error) {
      if (error.code === "EACCES") {
        throw new Error(`Permission denied: ${resolvedKeyPath}`);
      } else if (error.code === "ENOENT") {
        throw new Error(`Key file not found: ${resolvedKeyPath}`);
      }
      throw error;
    }

    const content = await fs.readFile(config.keyFilename, "utf-8");
    const keyData = JSON.parse(content);

    if (!keyData.type || keyData.type !== "service_account") {
      throw new Error("Invalid service account file");
    }
  }

  if (!/^[a-z0-9-]+$/.test(config.projectId)) {
    throw new Error("Invalid project ID format");
  }
}

// ---------------- ARG PARSER ----------------

function parseArgs() {
  const args = process.argv.slice(2);
  const config = { projectId: "", location: "US" };

  for (let i = 0; i < args.length; i++) {
    const key = args[i].replace("--", "");
    const value = args[i + 1];

    if (!value) throw new Error(`Missing value for ${key}`);

    switch (key) {
      case "project-id":
        config.projectId = value;
        break;
      case "location":
        config.location = value;
        break;
      case "key-file":
        config.keyFilename = value;
        break;
      case "config-file":
        config.configFile = value;
        break;
      case "maximum-bytes-billed":
        config.maximumBytesBilled = value;
        break;
      default:
        throw new Error(`Unknown argument ${key}`);
    }

    i++;
  }

  if (!config.projectId) {
    throw new Error("Missing --project-id");
  }

  return config;
}

// ---------------- CONFIG LOADER ----------------

function parseFieldRestrictionMap(raw) {
  if (!raw || typeof raw !== "object") return {};

  const result = {};
  for (const [table, fields] of Object.entries(raw)) {
    result[table.toLowerCase()] = fields.map((f) => f.toLowerCase());
  }
  return result;
}

async function loadConfiguration(configFile) {
  if (!configFile) {
    return { protectionMode: "off", maximumBytesBilled: "1000000000" };
  }

  const file = await fs.readFile(path.resolve(configFile), "utf-8");
  const parsed = JSON.parse(file);

  const max = parsed.maximumBytesBilled;

  if (parsed.protectionMode === "allowedTables") {
    return {
      protectionMode: "allowedTables",
      maximumBytesBilled: max,
      allowedTables: parsed.allowedTables.map((t) => t.toLowerCase()),
      preventedFieldsInAllowedTables: parseFieldRestrictionMap(
        parsed.preventedFieldsInAllowedTables
      ),
    };
  }

  if (parsed.protectionMode === "autoProtect") {
    return {
      protectionMode: "autoProtect",
      maximumBytesBilled: max,
      preventedFields: parseFieldRestrictionMap(parsed.preventedFields),
    };
  }

  return { protectionMode: "off", maximumBytesBilled: max };
}

// ---------------- SERVER ----------------

const server = new Server(
  { name: "mcp-server/bigquery", version: "0.1.0" },
  { capabilities: { resources: {}, tools: {} } }
);

// ---------------- INIT ----------------

try {
  config = parseArgs();
  await validateConfig(config);

  bigquery = new BigQuery({
    projectId: config.projectId,
    keyFilename: config.keyFilename,
  });

  resourceBaseUrl = new URL(`bigquery://${config.projectId}`);

  bigqueryConfig = await loadConfiguration(config.configFile);

  if (bigqueryConfig.protectionMode === "autoProtect") {
    await runDailyScanIfNeeded(bigquery, config.configFile, config.location);
  }
} catch (err) {
  console.error(err);
  process.exit(1);
}

// ---------------- HANDLERS ----------------

server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "query",
        description: "Run BigQuery SQL",
        inputSchema: {
          type: "object",
          properties: {
            sql: { type: "string" },
          },
        },
      },
    ],
  };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name !== "query") {
    throw new Error("Unknown tool");
  }

  let sql = request.params.arguments.sql;

  try {
    switch (bigqueryConfig.protectionMode) {
      case "allowedTables":
        enforceAllowedTables(sql, bigqueryConfig.allowedTables);
        break;
      case "autoProtect":
        enforceFieldRestrictions(sql, bigqueryConfig.preventedFields);
        break;
    }

    const [job] = await bigquery.createQueryJob({
      query: sql,
      dryRun: true,
    });

    validateIsSelectStatement(
      job.metadata?.statistics?.query?.statementType
    );

    const [rows] = await bigquery.query({
      query: sql,
      location: config.location,
      maximumBytesBilled: bigqueryConfig.maximumBytesBilled,
    });

    return {
      content: [{ type: "text", text: JSON.stringify(rows) }],
      isError: false,
    };
  } catch (err) {
    return {
      content: [{ type: "text", text: err.message }],
      isError: true,
    };
  }
});

// ---------------- RUN ----------------

async function run() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("MCP BigQuery server running...");
}

run();