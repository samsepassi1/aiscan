import * as path from 'path';
import * as vscode from 'vscode';
import {
  LanguageClient,
  LanguageClientOptions,
  ServerOptions,
  TransportKind,
} from 'vscode-languageclient/node';

let client: LanguageClient;

export function activate(context: vscode.ExtensionContext): void {
  const config = vscode.workspace.getConfiguration('aiscan');

  if (!config.get<boolean>('enabled', true)) {
    return;
  }

  // Server module path
  const serverModule = context.asAbsolutePath(path.join('out', 'server.js'));

  const serverOptions: ServerOptions = {
    run: { module: serverModule, transport: TransportKind.ipc },
    debug: {
      module: serverModule,
      transport: TransportKind.ipc,
      options: { execArgv: ['--nolazy', '--inspect=6009'] },
    },
  };

  const clientOptions: LanguageClientOptions = {
    documentSelector: [
      { scheme: 'file', language: 'python' },
      { scheme: 'file', language: 'javascript' },
      { scheme: 'file', language: 'typescript' },
      { scheme: 'file', language: 'go' },
      { scheme: 'file', language: 'java' },
    ],
    synchronize: {
      configurationSection: 'aiscan',
    },
  };

  client = new LanguageClient('aiscan', 'aiscan Security Scanner', serverOptions, clientOptions);
  client.start();

  // Register: Scan Current File
  context.subscriptions.push(
    vscode.commands.registerCommand('aiscan.scanFile', async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('aiscan: No active file to scan.');
        return;
      }
      await client
        .sendRequest('aiscan/scanFile', { uri: editor.document.uri.toString() })
        .catch((err: Error) => {
          vscode.window.showErrorMessage(`aiscan: Scan failed — ${err.message}`);
        });
    })
  );

  // Register: Scan Workspace
  context.subscriptions.push(
    vscode.commands.registerCommand('aiscan.scanWorkspace', async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders || folders.length === 0) {
        vscode.window.showWarningMessage('aiscan: No workspace folder open.');
        return;
      }
      await vscode.window.withProgress(
        { location: vscode.ProgressLocation.Notification, title: 'aiscan: Scanning workspace…' },
        async () => {
          await client
            .sendRequest('aiscan/scanWorkspace', { uri: folders[0].uri.toString() })
            .catch((err: Error) => {
              vscode.window.showErrorMessage(`aiscan: Workspace scan failed — ${err.message}`);
            });
        }
      );
    })
  );

  // Register: Clear Diagnostics
  context.subscriptions.push(
    vscode.commands.registerCommand('aiscan.clearDiagnostics', () => {
      client.sendNotification('aiscan/clearDiagnostics', {});
    })
  );

  // Register: View Remediation — wired up by the QuickFix CodeAction below.
  // The full remediation text is stored on diag.message; show it in a modal.
  context.subscriptions.push(
    vscode.commands.registerCommand(
      'aiscan.viewRemediation',
      (diag: vscode.Diagnostic) => {
        const code = typeof diag.code === 'object' ? diag.code.value : diag.code;
        vscode.window.showInformationMessage(
          `aiscan ${code ?? ''}: ${diag.message}`,
          { modal: true }
        );
      }
    )
  );

  // CodeAction provider — "View remediation" and "Suppress finding"
  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [
        { language: 'python' },
        { language: 'javascript' },
        { language: 'typescript' },
        { language: 'go' },
        { language: 'java' },
      ],
      new AiscanCodeActionProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );
}

export function deactivate(): Thenable<void> | undefined {
  if (!client) {
    return undefined;
  }
  return client.stop();
}


class AiscanCodeActionProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    document: vscode.TextDocument,
    range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    const actions: vscode.CodeAction[] = [];

    for (const diag of context.diagnostics) {
      if (diag.source !== 'aiscan') {
        continue;
      }

      // "View remediation" action — opens a quick-pick with the remediation text
      const remediationAction = new vscode.CodeAction(
        `aiscan: View remediation for ${diag.code}`,
        vscode.CodeActionKind.QuickFix
      );
      remediationAction.diagnostics = [diag];
      remediationAction.command = {
        title: 'View remediation',
        command: 'aiscan.viewRemediation',
        arguments: [diag],
      };
      actions.push(remediationAction);

      // "Suppress finding" action — inserts an aiscan: suppress comment.
      // The comment syntax is language-aware so the inserted text is an
      // actual comment and the aggregator's per-language matcher recognises
      // it. # is Python; // covers JS/TS/Go/Java.
      const suppressAction = new vscode.CodeAction(
        `aiscan: Suppress ${diag.code} on this line`,
        vscode.CodeActionKind.QuickFix
      );
      suppressAction.diagnostics = [diag];
      suppressAction.edit = new vscode.WorkspaceEdit();
      const line = document.lineAt(diag.range.start.line);
      const marker =
        document.languageId === 'python' ? '# aiscan: suppress' : '// aiscan: suppress';
      suppressAction.edit.insert(
        document.uri,
        new vscode.Position(diag.range.start.line, line.text.length),
        `  ${marker}`
      );
      actions.push(suppressAction);
    }

    return actions;
  }
}
