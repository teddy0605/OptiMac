//
//  OptiMacApp.swift
//  OptiMac
//
//  Created by Luke Edgar on 27/10/2025.
//

import SwiftUI
import AppKit

// AppDelegate to help activate app and bring windows to front.
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // Nothing special here; StatusBarController will be set up by the App.
        runSelfTestIfRequested()
    }

    #if DEBUG
    // Diagnostics: run the task runner in the real app context and log the
    // results, so sandbox/TCC failures can be told apart from task bugs.
    private func runSelfTestIfRequested() {
        guard CommandLine.arguments.contains("--optimac-selftest") else { return }
        let commands = [
            "defaults write com.apple.dock OptimacProbe -int 0 && defaults delete com.apple.dock OptimacProbe && echo dock-ok",
            "defaults write NSGlobalDomain OptimacProbe -bool true && defaults delete NSGlobalDomain OptimacProbe && echo nsglobal-ok",
            "rm -rf ~/Library/Caches/* 2>/dev/null; ls ~/Library/Caches && echo caches-ok",
        ]
        var lines: [String] = []
        for command in commands {
            let outcome = ShellRunner.run(command)
            lines.append("$ \(command)\nexit=\(outcome.code)\n\(outcome.output)\n")
        }
        try? lines.joined(separator: "\n")
            .write(toFile: "/tmp/optimac-selftest.log", atomically: true, encoding: .utf8)
    }
    #endif

    func openMainAppWindow() {
        // Activate the app and bring the main window to front
        NSApp.activate(ignoringOtherApps: true)
        // If there’s no key window yet, SwiftUI will create one from the WindowGroup
    }
}

@main
struct OptiMacApp: App {
    // Single shared monitor for both menu bar and main UI
    @StateObject private var systemMonitor: SystemMonitor

    // AppKit delegate
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    // Keep the status bar controller alive for the app lifetime
    @State private var statusBarController: StatusBarController?

    init() {
        let monitor = SystemMonitor()
        _systemMonitor = StateObject(wrappedValue: monitor)
        _statusBarController = State(initialValue: nil)
    }

    var body: some Scene {
        WindowGroup {
            ContentView(systemMonitor: systemMonitor)
                .onAppear {
                    if statusBarController == nil {
                        statusBarController = StatusBarController(
                            systemMonitor: systemMonitor,
                            openMainApp: { [weak appDelegate] in
                                appDelegate?.openMainAppWindow()
                            }
                        )
                    }
                }
        }
        .commands {
            CommandGroup(after: .appInfo) {
                Button("Open OptiMac") {
                    openMainApp()
                }
                .keyboardShortcut("o", modifiers: [.command, .shift])
            }
        }
    }

    private func openMainApp() {
        appDelegate.openMainAppWindow()
    }
}
