"use strict";

const fs = require("fs");
const ts = require("typescript");

function stablePosition(sourceFile, node) {
  return {
    line_start: sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1,
    line_end: sourceFile.getLineAndCharacterOfPosition(node.getEnd()).line + 1,
  };
}

function previewForNode(sourceFile, node) {
  const text = node.getText(sourceFile).replace(/\s+/g, " ").trim();
  return text.slice(0, 120);
}

function symbolNameForNode(node) {
  if (node.name && ts.isIdentifier(node.name)) {
    return node.name.text;
  }
  return null;
}

function statementKindForNode(node) {
  return ts.SyntaxKind[node.kind] || "Unknown";
}

function detectSymbolFromStatement(node) {
  if (ts.isFunctionDeclaration(node)) {
    return {
      kind: "function",
      name: symbolNameForNode(node) || "anonymous_function",
    };
  }
  if (ts.isClassDeclaration(node)) {
    return {
      kind: "class",
      name: symbolNameForNode(node) || "anonymous_class",
    };
  }
  if (ts.isMethodDeclaration(node)) {
    const methodName = node.name && ts.isIdentifier(node.name) ? node.name.text : "anonymous_method";
    return {
      kind: "method",
      name: methodName,
    };
  }
  if (ts.isVariableStatement(node)) {
    for (const declaration of node.declarationList.declarations) {
      if (!ts.isIdentifier(declaration.name) || !declaration.initializer) {
        continue;
      }
      if (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer)) {
        return {
          kind: "function",
          name: declaration.name.text,
        };
      }
    }
  }
  return null;
}

function main() {
  const filePath = process.argv[2];
  if (!filePath) {
    console.error("Missing file path.");
    process.exit(1);
  }

  const content = fs.readFileSync(filePath, "utf8");
  const scriptKind = filePath.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS;
  const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true, scriptKind);

  const symbols = [];
  const statements = [];
  const containerStack = [];

  function visit(node) {
    if (ts.isBlock(node) || ts.isSourceFile(node)) {
      ts.forEachChild(node, visit);
      return;
    }

    const symbol = detectSymbolFromStatement(node);
    let currentContainer = containerStack.length ? containerStack[containerStack.length - 1] : null;

    if (symbol) {
      const position = stablePosition(sourceFile, node);
      const symbolPayload = {
        kind: symbol.kind,
        name: symbol.name,
        line_start: position.line_start,
        line_end: position.line_end,
        container_kind: currentContainer ? currentContainer.kind : null,
        container_name: currentContainer ? currentContainer.name : null,
        is_exported: (ts.getCombinedModifierFlags(node) & ts.ModifierFlags.Export) !== 0,
      };
      symbols.push(symbolPayload);
      currentContainer = { kind: symbol.kind, name: symbol.name };
    }

    if (ts.isStatement(node) && !ts.isBlock(node)) {
      const position = stablePosition(sourceFile, node);
      statements.push({
        kind: statementKindForNode(node),
        line_start: position.line_start,
        line_end: position.line_end,
        preview: previewForNode(sourceFile, node),
        container_kind: currentContainer ? currentContainer.kind : null,
        container_name: currentContainer ? currentContainer.name : null,
      });
    }

    if (symbol) {
      containerStack.push(currentContainer);
      ts.forEachChild(node, visit);
      containerStack.pop();
      return;
    }

    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  process.stdout.write(JSON.stringify({ symbols, statements }));
}

main();
