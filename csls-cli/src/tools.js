// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Causal-Slash Protocol Developers

import fs from "node:fs";
import path from "node:path";
import { exec, spawn } from "node:child_process";

export const toolDefinitions = [
  {
    type: "function",
    function: {
      name: "bash",
      description: "Execute a shell command in the project directory. Use this to run build scripts, tests, package managers, or inspect system state.",
      parameters: {
        type: "object",
        properties: {
          command: { type: "string", description: "The bash command line to execute." },
          timeout_ms: { type: "number", description: "Optional execution timeout in milliseconds (default: 60000)." },
        },
        required: ["command"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "read_file",
      description: "Read the complete contents or line range of a file from the workspace.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Relative or absolute file path to read." },
          start_line: { type: "number", description: "Optional 1-indexed starting line number." },
          end_line: { type: "number", description: "Optional 1-indexed ending line number." },
        },
        required: ["path"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "write_file",
      description: "Create a new file or completely overwrite an existing file with given content. Parent directories will be automatically created.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Relative or absolute path to write." },
          content: { type: "string", description: "Full content to write to the file." },
        },
        required: ["path", "content"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "edit_file",
      description: "Modify an existing file by replacing an exact block of existing text with new content.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "File path to modify." },
          target_content: { type: "string", description: "Exact target text string to find and replace." },
          replacement_content: { type: "string", description: "Replacement text to insert." },
        },
        required: ["path", "target_content", "replacement_content"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "glob",
      description: "Find files in the workspace matching a pattern (e.g. '**/*.ts', 'src/**/*.py').",
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "Pattern to match." },
        },
        required: ["pattern"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "grep",
      description: "Search for a regex or string pattern inside files across the workspace.",
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "Search query or regular expression." },
          path: { type: "string", description: "Optional directory or file path to search inside (default: current directory)." },
        },
        required: ["pattern"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "list_dir",
      description: "List the directory contents with file types and sizes.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Directory path to list (default: current directory)." },
        },
      },
    },
  },
];

export async function executeTool(name, args, cwd = process.cwd()) {
  try {
    switch (name) {
      case "bash":
        return await runBash(args.command, cwd, args.timeout_ms || 60000);
      case "read_file":
        return await runReadFile(args.path, cwd, args.start_line, args.end_line);
      case "write_file":
        return await runWriteFile(args.path, args.content, cwd);
      case "edit_file":
        return await runEditFile(args.path, args.target_content, args.replacement_content, cwd);
      case "glob":
        return await runGlob(args.pattern, cwd);
      case "grep":
        return await runGrep(args.pattern, args.path, cwd);
      case "list_dir":
        return await runListDir(args.path || ".", cwd);
      default:
        return { error: `Unknown tool: ${name}` };
    }
  } catch (err) {
    return { error: err.message || String(err) };
  }
}

function resolvePath(filePath, cwd) {
  if (path.isAbsolute(filePath)) return filePath;
  return path.resolve(cwd, filePath);
}

function runBash(command, cwd, timeoutMs) {
  return new Promise((resolve) => {
    exec(command, { cwd, timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        resolve({
          exit_code: err.code || 1,
          stdout: stdout || "",
          stderr: stderr || err.message,
          error: `Process failed with exit code ${err.code || 1}`,
        });
      } else {
        resolve({
          exit_code: 0,
          stdout: stdout || "(empty stdout)",
          stderr: stderr || "",
        });
      }
    });
  });
}

function runReadFile(filePath, cwd, startLine, endLine) {
  const fullPath = resolvePath(filePath, cwd);
  if (!fs.existsSync(fullPath)) {
    return { error: `File not found: ${filePath}` };
  }
  const stat = fs.statSync(fullPath);
  if (stat.isDirectory()) {
    return { error: `Path is a directory, not a file: ${filePath}` };
  }

  const content = fs.readFileSync(fullPath, "utf-8");
  const lines = content.split("\n");

  const start = startLine ? Math.max(1, startLine) : 1;
  const end = endLine ? Math.min(lines.length, endLine) : lines.length;

  const numbered = [];
  for (let i = start; i <= end; i++) {
    numbered.push(`${String(i).padStart(5, " ")}: ${lines[i - 1]}`);
  }

  return {
    path: filePath,
    total_lines: lines.length,
    start_line: start,
    end_line: end,
    content: numbered.join("\n"),
  };
}

function runWriteFile(filePath, content, cwd) {
  const fullPath = resolvePath(filePath, cwd);
  const dir = path.dirname(fullPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(fullPath, content, "utf-8");
  return {
    path: filePath,
    bytes_written: Buffer.byteLength(content, "utf-8"),
    status: "success",
  };
}

function runEditFile(filePath, targetContent, replacementContent, cwd) {
  const fullPath = resolvePath(filePath, cwd);
  if (!fs.existsSync(fullPath)) {
    return { error: `File not found: ${filePath}` };
  }
  const content = fs.readFileSync(fullPath, "utf-8");
  if (!content.includes(targetContent)) {
    return { error: `Target content not found in ${filePath}` };
  }
  const occurrences = content.split(targetContent).length - 1;
  if (occurrences > 1) {
    return { error: `Found ${occurrences} occurrences of target content. Target must be unique.` };
  }
  const newContent = content.replace(targetContent, replacementContent);
  fs.writeFileSync(fullPath, newContent, "utf-8");
  return {
    path: filePath,
    status: "success",
    modified: true,
  };
}

function runGlob(pattern, cwd) {
  return new Promise((resolve) => {
    const cmd = `find . -type f -name "${pattern.replace(/\*\*\//g, "")}" | head -n 100`;
    exec(cmd, { cwd }, (err, stdout) => {
      if (err) {
        resolve({ error: err.message });
      } else {
        const matches = stdout.trim().split("\n").filter(Boolean);
        resolve({ count: matches.length, matches });
      }
    });
  });
}

function runGrep(pattern, targetPath = ".", cwd) {
  return new Promise((resolve) => {
    const fullPath = resolvePath(targetPath, cwd);
    const cmd = `grep -rnI --exclude-dir=".git" --exclude-dir="node_modules" "${pattern}" "${fullPath}" | head -n 100`;
    exec(cmd, { cwd }, (err, stdout, stderr) => {
      const lines = (stdout || "").trim().split("\n").filter(Boolean);
      resolve({
        count: lines.length,
        results: lines.slice(0, 100),
      });
    });
  });
}

function runListDir(dirPath, cwd) {
  const fullPath = resolvePath(dirPath, cwd);
  if (!fs.existsSync(fullPath)) {
    return { error: `Directory not found: ${dirPath}` };
  }
  const entries = fs.readdirSync(fullPath, { withFileTypes: true });
  const list = entries.map((e) => {
    return {
      name: e.name,
      type: e.isDirectory() ? "directory" : "file",
    };
  });
  return {
    path: dirPath,
    total: list.length,
    entries: list.slice(0, 100),
  };
}
