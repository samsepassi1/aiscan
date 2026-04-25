import * as cp from 'child_process';
import * as path from 'path';
import {
  createConnection,
  TextDocuments,
  Diagnostic,
  DiagnosticSeverity,
  ProposedFeatures,
  InitializeParams,
  InitializeResult,
  TextDocumentSyncKind,
} from 'vscode-languageserver/node';
import { TextDocument } from 'vscode-languageserver-textdocument';

const connection = createConnection(ProposedFeatures.all);
const documents: TextDocuments<TextDocument> = new TextDocuments(TextDocument);

let aiscanExecutable = 'aiscan';
let llmEnabled = false;
let minSeverity = 'LOW';
let llmProvider = 'anthropic';
let llmModel = 'claude-sonnet-4-6';
let llmBaseUrl = '';

connection.onInitialize((_params: InitializeParams): InitializeResult => {
  return {
    capabilities: {
      textDocumentSync: TextDocumentSyncKind.Incremental,
    },
  };
});

connection.onDidChangeConfiguration((change) => {
  const config = change.settings?.aiscan || {};
  aiscanExecutable = config.executablePath || 'aiscan';
  llmEnabled = config.llmEnabled || false;
  minSeverity = config.severity || 'LOW';
  llmProvider = config.llmProvider || 'anthropic';
  llmModel = config.llmModel || 'claude-sonnet-4-6';
  llmBaseUrl = config.llmBaseUrl || '';
  // Re-validate all open documents on config change
  documents.all().forEach(validateDocument);
});

documents.onDidOpen((event) => validateDocument(event.document));
documents.onDidSave((event) => validateDocument(event.document));

async function validateDocument(textDocument: TextDocument): Promise<void> {
  const uri = textDocument.uri;
  const filePath = uri.replace(/^file:\/\//, '');

  const args = [
    'scan',
    filePath,
    '--format', 'json',
    '--severity', minSeverity,
  ];

  if (llmEnabled) {
    args.push('--llm');
    args.push('--llm-provider', llmProvider);
    args.push('--llm-model', llmModel);
    if (llmBaseUrl) {
      args.push('--llm-base-url', llmBaseUrl);
    }
  }

  let stdout = '';
  let stderr = '';

  try {
    await new Promise<void>((resolve, _reject) => {
      const proc = cp.spawn(aiscanExecutable, args, { shell: false });
      proc.stdout.on('data', (d: Buffer) => { stdout += d.toString(); });
      proc.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
      proc.on('close', () => resolve());
      proc.on('error', () => resolve()); // aiscan not installed → silent
    });

    const diagnostics: Diagnostic[] = [];

    if (stdout.trim()) {
      const result = JSON.parse(stdout);
      const findings: any[] = result.findings || [];

      for (const finding of findings) {
        if (finding.suppressed) continue;

        const severity = mapSeverity(finding.severity);
        const diag: Diagnostic = {
          severity,
          range: {
            start: { line: Math.max(0, (finding.line_start || 1) - 1), character: finding.column_start || 0 },
            end: { line: Math.max(0, (finding.line_end || finding.line_start || 1) - 1), character: finding.column_end || 999 },
          },
          message: `${finding.message}\n\nRemediation: ${finding.remediation}`,
          source: 'aiscan',
          code: finding.rule_id,
        };
        diagnostics.push(diag);
      }
    }

    connection.sendDiagnostics({ uri, diagnostics });
  } catch (_e) {
    // JSON parse error or spawn error — clear diagnostics and continue
    connection.sendDiagnostics({ uri, diagnostics: [] });
  }
}

function mapSeverity(sev: string): DiagnosticSeverity {
  switch (sev) {
    case 'CRITICAL':
    case 'HIGH':
      return DiagnosticSeverity.Error;
    case 'MEDIUM':
      return DiagnosticSeverity.Warning;
    case 'LOW':
      return DiagnosticSeverity.Information;
    default:
      return DiagnosticSeverity.Hint;
  }
}

// Handle custom requests from the extension client
connection.onRequest('aiscan/scanFile', async (params: { uri: string }) => {
  const filePath = params.uri.replace(/^file:\/\//, '');
  const doc = documents.get(params.uri);
  if (doc) {
    await validateDocument(doc);
  }
});

connection.onRequest('aiscan/scanWorkspace', async (params: { uri: string }) => {
  documents.all().forEach(validateDocument);
});

connection.onNotification('aiscan/clearDiagnostics', () => {
  documents.all().forEach((doc) => {
    connection.sendDiagnostics({ uri: doc.uri, diagnostics: [] });
  });
});

documents.listen(connection);
connection.listen();
