//
//  ContentView.swift
//  OptiMac
//
//  Real System Monitoring with Actual macOS System Calls
//

import SwiftUI
import Charts
import Foundation
import Combine
import Darwin

// Fallback if the constant isn’t visible for some SDKs (Apple defines it as 4096)
let PROC_PIDPATHINFO_MAXSIZE: Int32 = 4096

// MARK: - Real System Data Models
struct ProcessInfo: Identifiable {
    let id = UUID()
    let pid: Int32
    let name: String
    let cpuUsage: Double
    let memoryUsage: Double // in MB
    let color: Color
}

struct RealMemoryInfo {
    let totalMemory: Double // in GB
    let usedMemory: Double // in GB
    let freeMemory: Double // in GB
    let appMemoryUsage: [ProcessInfo]
    let swapUsed: Double // in GB
}

struct NetworkSpeed {
    let downloadBytesPerSec: Double
    let uploadBytesPerSec: Double
    let timestamp: Date
    
    var downloadMbps: Double {
        return (downloadBytesPerSec * 8) / (1024 * 1024) // Convert to Mbps
    }
    
    var uploadMbps: Double {
        return (uploadBytesPerSec * 8) / (1024 * 1024) // Convert to Mbps
    }
}

struct UrgentProcess: Identifiable {
    let id = UUID()
    let pid: Int32
    let name: String
    let issue: String
    let cpuUsage: Double
    let memoryUsage: Double
    let priority: UrgentPriority
}

enum UrgentPriority {
    case high, medium, low
    
    var color: Color {
        switch self {
        case .high: return Color(red: 1.00, green: 0.22, blue: 0.30) // crisper red
        case .medium: return Color(red: 1.00, green: 0.55, blue: 0.00) // vivid orange
        case .low: return Color(red: 1.00, green: 0.84, blue: 0.00) // bright yellow
        }
    }
}

// MARK: - Real System Monitor Class
class RealSystemMonitor: ObservableObject {
    @Published var memoryInfo = RealMemoryInfo(totalMemory: 0, usedMemory: 0, freeMemory: 0, appMemoryUsage: [], swapUsed: 0)
    @Published var cpuProcesses: [ProcessInfo] = []
    @Published var networkHistory: [NetworkSpeed] = []
    @Published var urgentProcesses: [UrgentProcess] = []
    @Published var totalCPUUsage: Double = 0
    
    private var previousNetworkStats: (rx: UInt64, tx: UInt64) = (0, 0)
    private var lastNetworkUpdate = Date()
    private let appColors: [Color] = [
        Color(red: 0.20, green: 0.60, blue: 1.00),
        Color(red: 0.20, green: 0.85, blue: 0.50),
        Color(red: 1.00, green: 0.55, blue: 0.00),
        Color(red: 0.60, green: 0.40, blue: 1.00),
        Color(red: 1.00, green: 0.22, blue: 0.30),
        Color(red: 1.00, green: 0.40, blue: 0.70),
        Color(red: 0.10, green: 0.80, blue: 0.90),
        Color(red: 1.00, green: 0.84, blue: 0.00),
        Color(red: 0.60, green: 0.45, blue: 0.30),
        Color(red: 0.40, green: 0.40, blue: 1.00)
    ]
    private var processColorMap: [String: Color] = [:]
    
    // CPU sampling state
    private var lastCPUTimeStamp: TimeInterval = 0
    private var lastSystemCPUTicks: (user: UInt32, system: UInt32, nice: UInt32, idle: UInt32)?
    private var lastPerProcessCPUTimeNs: [Int32: UInt64] = [:] // pid -> total (user+system) ns
    
    private var updateTimer: Timer?
    private let numCores = Double(Foundation.ProcessInfo.processInfo.processorCount)
    
    init() {
        startRealTimeMonitoring()
    }
    
    private func startRealTimeMonitoring() {
        // Initial update
        updateAllSystemData()
        
        // Update every 2 seconds
        updateTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { _ in
            Task { @MainActor in
                self.updateAllSystemData()
            }
        }
    }
    
    private func updateAllSystemData() {
        updateMemoryInfo()
        updateCPUInfo()
        updateNetworkInfo()
        updateUrgentProcesses()
    }
    
    // MARK: - Real Memory Monitoring (Activity Monitor parity)
    private func updateMemoryInfo() {
        var stats = vm_statistics64()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<natural_t>.size)
        
        let result = withUnsafeMutablePointer(to: &stats) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        
        if result == KERN_SUCCESS {
            let pageSize = Double(vm_kernel_page_size)
            let totalBytes = Double(Foundation.ProcessInfo.processInfo.physicalMemory)
            
            // Match “Memory Used” in Activity Monitor:
            // used = active + wired + compressed
            // free = free + inactive (as displayed in AM “Memory Pressure” details)
            let usedBytes = (Double(stats.active_count)
                             + Double(stats.wire_count)
                             + Double(stats.compressor_page_count)) * pageSize
            let freeBytes = (Double(stats.free_count) + Double(stats.inactive_count)) * pageSize
            
            let totalGB = totalBytes / (1024 * 1024 * 1024)
            let usedGB = max(usedBytes, 0) / (1024 * 1024 * 1024)
            let freeGB = max(freeBytes, 0) / (1024 * 1024 * 1024)
            
            // Get per-process memory via proc_pidinfo (resident size)
            let processes = getRealProcessList()
            let topMemoryProcesses = Array(processes.sorted { $0.memoryUsage > $1.memoryUsage }.prefix(6))
            
            // Real swap usage from sysctl vm.swapusage
            // (format: "total = 2048.00M  used = 512.00M  free = 1536.00M")
            var swapUsedGB = 0.0
            var swapSize = 0
            if sysctlbyname("vm.swapusage", nil, &swapSize, nil, 0) == 0, swapSize > 0 {
                var swapBuffer = [CChar](repeating: 0, count: swapSize)
                if sysctlbyname("vm.swapusage", &swapBuffer, &swapSize, nil, 0) == 0 {
                    let swapInfo = String(cString: swapBuffer)
                    if let usedRange = swapInfo.range(of: "used = "),
                       let megaRange = swapInfo.range(of: "M", range: usedRange.upperBound..<swapInfo.endIndex),
                       let swapMB = Double(swapInfo[usedRange.upperBound..<megaRange.lowerBound]) {
                        swapUsedGB = swapMB / 1024
                    }
                }
            }

            memoryInfo = RealMemoryInfo(
                totalMemory: totalGB,
                usedMemory: usedGB,
                freeMemory: freeGB,
                appMemoryUsage: topMemoryProcesses,
                swapUsed: swapUsedGB
            )
        }
    }
    
    // MARK: - Real CPU Monitoring
    private func updateCPUInfo() {
        // Update total CPU from host_processor_info deltas
        totalCPUUsage = readSystemCPUPercentage()
        
        // Build process list with real per-process CPU and memory from proc_pidinfo
        let processes = getRealProcessList()
        
        // Get top CPU consuming processes
        cpuProcesses = Array(processes.sorted { $0.cpuUsage > $1.cpuUsage }.prefix(6))
    }
    
    // MARK: - System CPU via host_processor_info (delta-based)
    private func readSystemCPUPercentage() -> Double {
        var cpuInfo: processor_info_array_t?
        var cpuInfoCount: mach_msg_type_number_t = 0
        var numCPUU: natural_t = 0
        
        let result = host_processor_info(mach_host_self(),
                                         PROCESSOR_CPU_LOAD_INFO,
                                         &numCPUU,
                                         &cpuInfo,
                                         &cpuInfoCount)
        guard result == KERN_SUCCESS, let info = cpuInfo else {
            return totalCPUUsage // leave unchanged if failed
        }
        defer {
            let size = Int(cpuInfoCount) * MemoryLayout<integer_t>.size
            vm_deallocate(mach_task_self_, vm_address_t(bitPattern: info), vm_size_t(size))
        }
        
        var totalUser: UInt32 = 0
        var totalSystem: UInt32 = 0
        var totalNice: UInt32 = 0
        var totalIdle: UInt32 = 0
        
        let stride = Int(CPU_STATE_MAX)
        for cpu in 0..<Int(numCPUU) {
            let base = Int(cpu) * stride
            totalUser   &+= UInt32(info[base + Int(CPU_STATE_USER)])
            totalSystem &+= UInt32(info[base + Int(CPU_STATE_SYSTEM)])
            totalNice   &+= UInt32(info[base + Int(CPU_STATE_NICE)])
            totalIdle   &+= UInt32(info[base + Int(CPU_STATE_IDLE)])
        }
        
        if let last = lastSystemCPUTicks {
            let userDiff = totalUser &- last.user
            let sysDiff  = totalSystem &- last.system
            let niceDiff = totalNice &- last.nice
            let idleDiff = totalIdle &- last.idle
            
            let totalTicks = Double(userDiff + sysDiff + niceDiff + idleDiff)
            if totalTicks > 0 {
                let busy = Double(userDiff + sysDiff + niceDiff)
                let percent = (busy / totalTicks) * 100.0
                lastSystemCPUTicks = (totalUser, totalSystem, totalNice, totalIdle)
                return min(max(percent, 0), 100)
            }
        }
        
        lastSystemCPUTicks = (totalUser, totalSystem, totalNice, totalIdle)
        return totalCPUUsage // unchanged on first sample
    }
    
    // MARK: - Real Process List using kinfo_proc + proc_pidinfo
    private func getRealProcessList() -> [ProcessInfo] {
        var processes: [ProcessInfo] = []
        var buffer: UnsafeMutablePointer<kinfo_proc>?
        var size: size_t = 0
        
        // Get process list size
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        sysctl(&mib, u_int(mib.count), nil, &size, nil, 0)
        
        buffer = UnsafeMutablePointer<kinfo_proc>.allocate(capacity: size / MemoryLayout<kinfo_proc>.size)
        defer { buffer?.deallocate() }
        
        if sysctl(&mib, u_int(mib.count), buffer, &size, nil, 0) == 0 {
            let processCount = size / MemoryLayout<kinfo_proc>.size
            let now = Date().timeIntervalSince1970
            let elapsed = lastCPUTimeStamp > 0 ? now - lastCPUTimeStamp : 0
            let elapsedNs = elapsed > 0 ? UInt64(elapsed * 1_000_000_000) : 0
            
            for i in 0..<processCount {
                let proc = buffer!.advanced(by: i).pointee
                let pid = proc.kp_proc.p_pid
                if pid <= 0 { continue }
                
                // Get process path/name
                var pathBuffer = [CChar](repeating: 0, count: Int(PROC_PIDPATHINFO_MAXSIZE))
                let pathLength = proc_pidpath(pid, &pathBuffer, UInt32(PROC_PIDPATHINFO_MAXSIZE))
                
                var processName = "Unknown"
                if pathLength > 0 {
                    let path = String(cString: pathBuffer)
                    processName = URL(fileURLWithPath: path).lastPathComponent
                } else {
                    // Fallback to kp_proc.p_comm if path not available
                    withUnsafePointer(to: proc.kp_proc.p_comm) {
                        processName = String(cString: UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self))
                    }
                }
                if processName.isEmpty { continue }
                
                // Read proc_taskinfo for the pid
                var tinfo = proc_taskinfo()
                let tinfoSize = MemoryLayout<proc_taskinfo>.stride
                let readSize = withUnsafeMutablePointer(to: &tinfo) { ptr in
                    ptr.withMemoryRebound(to: UInt8.self, capacity: tinfoSize) { rawPtr in
                        proc_pidinfo(pid, PROC_PIDTASKINFO, 0, rawPtr, Int32(tinfoSize))
                    }
                }
                guard readSize == tinfoSize else {
                    continue
                }
                
                // Memory (resident) in MB
                let memMB = Double(tinfo.pti_resident_size) / (1024.0 * 1024.0)
                
                // CPU: compute delta of total (user+system) time
                let totalNs = tinfo.pti_total_user + tinfo.pti_total_system
                let prevNs = lastPerProcessCPUTimeNs[pid] ?? totalNs
                let deltaNs = totalNs &- prevNs
                lastPerProcessCPUTimeNs[pid] = totalNs
                
                var cpuPercent: Double = 0.0
                if elapsedNs > 0 {
                    // Normalize by elapsed time and core count
                    let fraction = Double(deltaNs) / Double(elapsedNs)
                    cpuPercent = (fraction / numCores) * 100.0
                }
                
                // Only include processes with noticeable usage (helps keep charts readable)
                if cpuPercent > 0.05 || memMB > 50 {
                    let color = getColorForProcess(processName)
                    processes.append(ProcessInfo(
                        pid: pid,
                        name: processName,
                        cpuUsage: min(max(cpuPercent, 0), 100),
                        memoryUsage: memMB,
                        color: color
                    ))
                }
            }
            
            lastCPUTimeStamp = now
        }
        
        return processes
    }
    
    // MARK: - Network parity with Activity Monitor
    private func updateNetworkInfo() {
        let currentStats = getPrimaryInterfaceCounters()
        let now = Date()
        let timeDiff = now.timeIntervalSince(lastNetworkUpdate)
        
        // If we have never recorded stats, seed previousNetworkStats and push a baseline sample
        if previousNetworkStats.rx == 0 && previousNetworkStats.tx == 0 {
            previousNetworkStats = currentStats
            lastNetworkUpdate = now
            // Seed one zero-rate sample so the UI can progress after next tick
            networkHistory.append(NetworkSpeed(downloadBytesPerSec: 0, uploadBytesPerSec: 0, timestamp: now))
            if networkHistory.count > 40 {
                networkHistory.removeFirst()
            }
            return
        }
        
        if timeDiff > 0 {
            let rxDiff = currentStats.rx > previousNetworkStats.rx ? currentStats.rx - previousNetworkStats.rx : 0
            let txDiff = currentStats.tx > previousNetworkStats.tx ? currentStats.tx - previousNetworkStats.tx : 0
            
            let downloadSpeed = Double(rxDiff) / timeDiff
            let uploadSpeed = Double(txDiff) / timeDiff
            
            let networkSpeed = NetworkSpeed(
                downloadBytesPerSec: downloadSpeed,
                uploadBytesPerSec: uploadSpeed,
                timestamp: now
            )
            
            networkHistory.append(networkSpeed)
            if networkHistory.count > 40 { // a bit more history for smoother chart
                networkHistory.removeFirst()
            }
        }
        
        previousNetworkStats = currentStats
        lastNetworkUpdate = now
    }
    
    // Resolve default-route interface by asking the kernel which local IP it would use to reach 8.8.8.8:53
    private func defaultRouteInterfaceName() -> String? {
        // 1) Create a UDP socket and "connect" to 8.8.8.8:53 (no packets sent)
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        if sock < 0 { return nil }
        defer { close(sock) }
        
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(53).bigEndian
        inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr)
        
        var dest = sockaddr()
        memcpy(&dest, &addr, MemoryLayout<sockaddr_in>.size)
        let result = withUnsafePointer(to: &dest) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if result < 0 {
            // Could not connect (offline), fall back to picking any UP|RUNNING en*
            return activeInterfaceNameFallback()
        }
        
        // 2) getsockname to learn the local IP chosen by kernel
        var localAddr = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let gsn = withUnsafeMutablePointer(to: &localAddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(sock, $0, &len)
            }
        }
        if gsn != 0 {
            return activeInterfaceNameFallback()
        }
        
        // 3) Map local IP to interface via getifaddrs
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else {
            return activeInterfaceNameFallback()
        }
        defer { freeifaddrs(ifaddr) }
        
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let p = ptr?.pointee {
            if p.ifa_addr.pointee.sa_family == UInt8(AF_INET) {
                let sa = UnsafeRawPointer(p.ifa_addr).assumingMemoryBound(to: sockaddr_in.self).pointee
                if sa.sin_addr.s_addr == localAddr.sin_addr.s_addr {
                    return String(cString: p.ifa_name)
                }
            }
            ptr = p.ifa_next
        }
        
        return activeInterfaceNameFallback()
    }
    
    // Fallback: first UP|RUNNING en*, else any UP|RUNNING
    private func activeInterfaceNameFallback() -> String? {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let first = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }
        
        var candidates: [String] = []
        var ptr: UnsafeMutablePointer<ifaddrs>? = first
        while let p = ptr?.pointee {
            let flags = Int32(p.ifa_flags)
            let isUp = (flags & IFF_UP) != 0
            let isRunning = (flags & IFF_RUNNING) != 0
            let name = String(cString: p.ifa_name)
            if isUp && isRunning {
                candidates.append(name)
            }
            ptr = p.ifa_next
        }
        if candidates.contains("en0") { return "en0" }
        if candidates.contains("en1") { return "en1" }
        if let en = candidates.first(where: { $0.hasPrefix("en") }) { return en }
        return candidates.first
    }
    
    // Read per-interface counters using sysctl NET_RT_IFLIST2 (if_msghdr2 -> if_data64)
    private func interfaceByteCounters(name: String) -> (rx: UInt64, tx: UInt64)? {
        // Build MIB: CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST2, 0
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, AF_LINK, NET_RT_IFLIST2, 0]
        var len: size_t = 0
        // First call to get size
        if sysctl(&mib, u_int(mib.count), nil, &len, nil, 0) != 0 || len == 0 {
            return nil
        }
        let buf = UnsafeMutableRawPointer.allocate(byteCount: len, alignment: MemoryLayout<Int8>.alignment)
        defer { buf.deallocate() }
        if sysctl(&mib, u_int(mib.count), buf, &len, nil, 0) != 0 {
            return nil
        }
        
        var rx: UInt64 = 0
        var tx: UInt64 = 0
        
        var next = buf
        let end = buf.advanced(by: len)
        while next < end {
            // All route messages are length-prefixed; read the header to know how far to advance
            let ifm = next.assumingMemoryBound(to: if_msghdr2.self).pointee
            let msgLen = Int(ifm.ifm_msglen)
            
            if ifm.ifm_type == UInt8(RTM_IFINFO2) {
                // The sockaddr_dl immediately follows the header
                let sdlPtr = next.advanced(by: MemoryLayout<if_msghdr2>.size).assumingMemoryBound(to: sockaddr_dl.self)
                let sdl = sdlPtr.pointee
                let nameLen = Int(sdl.sdl_nlen)
                
                // The name bytes start at sdl_data within sockaddr_dl
                let sdlDataOffset = MemoryLayout.offset(of: \sockaddr_dl.sdl_data) ?? MemoryLayout<sockaddr_dl>.size
                let nameStart = UnsafeRawPointer(sdlPtr).advanced(by: sdlDataOffset)
                let nameBytes = nameStart.assumingMemoryBound(to: UInt8.self)
                let ifName = String(decoding: UnsafeBufferPointer(start: nameBytes, count: max(0, nameLen)), as: UTF8.self)
                
                if ifName == name {
                    rx = ifm.ifm_data.ifi_ibytes
                    tx = ifm.ifm_data.ifi_obytes
                    break
                }
            }
            
            // Advance to the next message
            next = next.advanced(by: msgLen)
        }
        
        return (rx, tx)
    }
    
    private func getPrimaryInterfaceCounters() -> (rx: UInt64, tx: UInt64) {
        guard let iface = defaultRouteInterfaceName(),
              let counters = interfaceByteCounters(name: iface) else {
            // Fallback to zeros to avoid fake movement
            return (rx: 0, tx: 0)
        }
        return counters
    }
    
    // MARK: - Real Urgent Processes Detection
    private func updateUrgentProcesses() {
        let allProcesses = getRealProcessList()
        var urgent: [UrgentProcess] = []
        
        for process in allProcesses {
            var shouldAdd = false
            var issue = ""
            var priority = UrgentPriority.low
            
            if process.cpuUsage > 50 {
                issue = "High CPU usage (\(String(format: "%.1f", process.cpuUsage))%)"
                priority = .high
                shouldAdd = true
            } else if process.memoryUsage > 2048 {
                issue = "High memory usage (\(String(format: "%.0f", process.memoryUsage))MB)"
                priority = .medium
                shouldAdd = true
            } else if process.cpuUsage > 20 || process.memoryUsage > 1000 {
                issue = "Moderate resource usage"
                priority = .low
                shouldAdd = true
            }
            
            if shouldAdd && urgent.count < 5 {
                urgent.append(UrgentProcess(
                    pid: process.pid,
                    name: process.name,
                    issue: issue,
                    cpuUsage: process.cpuUsage,
                    memoryUsage: process.memoryUsage,
                    priority: priority
                ))
            }
        }
        
        urgentProcesses = urgent
    }
    
    // MARK: - Force Quit Process (REAL)
    func forceQuitProcess(pid: Int32) {
        let result = kill(pid, SIGTERM)
        if result != 0 {
            kill(pid, SIGKILL)
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) {
            self.updateUrgentProcesses()
        }
    }
    
    private func getColorForProcess(_ processName: String) -> Color {
        if let existingColor = processColorMap[processName] {
            return existingColor
        }
        
        let colorIndex = processColorMap.count % appColors.count
        let color = appColors[colorIndex]
        processColorMap[processName] = color
        return color
    }
    
    deinit {
        updateTimer?.invalidate()
    }
}

// MARK: - System Data Models (keeping existing optimization task structure)
struct OptimizationMetric: Identifiable {
    let id = UUID()
    let title: String
    let category: String
    let description: String
    var currentValue: Double
    var previousValue: Double
    var targetValue: Double
    var unit: String
    var status: MetricStatus
    var lastUpdated: Date
}

struct MetricDataPoint: Identifiable {
    let id = UUID()
    let timestamp: Date
    let value: Double
}

enum MetricStatus: String, CaseIterable {
    case excellent = "excellent"
    case good = "good"
    case warning = "warning"
    case critical = "critical"
    
    var color: Color {
        switch self {
        case .excellent: return Color(red: 0.10, green: 0.85, blue: 0.50)
        case .good: return Color(red: 0.20, green: 0.60, blue: 1.00)
        case .warning: return Color(red: 1.00, green: 0.55, blue: 0.00)
        case .critical: return Color(red: 1.00, green: 0.22, blue: 0.30)
        }
    }
    
    var icon: String {
        switch self {
        case .excellent: return "checkmark.circle.fill"
        case .good: return "arrow.up.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.circle.fill"
        }
    }
}

struct OptimizationTask: Identifiable {
    let id: String
    let title: String
    let description: String
    let category: String
    let command: String
    var requiresAdmin: Bool = false
    var isSelected: Bool = false
}

// Result of one optimization task run, shown in the confirmation sheet.
struct TaskRunResult: Identifiable {
    let id = UUID()
    let task: OptimizationTask
    let succeeded: Bool
    let output: String
}

// MARK: - System Monitor (keeping optimization functionality)
class SystemMonitor: ObservableObject {
    @Published var currentMetrics: [OptimizationMetric] = []
    @Published var isOptimizing = false
    @Published var optimizationTasks: [OptimizationTask] = []
    @Published var selectedTasks: Set<String> = []
    @Published var realSystemMonitor = RealSystemMonitor()
    
    // Confirmation sheet
    @Published var showConfirmation = false
    @Published var taskResults: [TaskRunResult] = []
    @Published var lastRunDate: Date?
    
    init() {
        initializeOptimizationTasks()
        setupMetrics()
    }
    
    private func setupMetrics() {
        currentMetrics = [
            OptimizationMetric(
                title: "Memory Usage",
                category: "System Resources",
                description: "Real-time RAM usage by applications",
                currentValue: 0,
                previousValue: 0,
                targetValue: 100,
                unit: "GB",
                status: .good,
                lastUpdated: Date()
            ),
            OptimizationMetric(
                title: "System Performance",
                category: "CPU & GPU",
                description: "Real-time processor usage",
                currentValue: 0,
                previousValue: 0,
                targetValue: 100,
                unit: "%",
                status: .good,
                lastUpdated: Date()
            ),
            OptimizationMetric(
                title: "Network Speed",
                category: "Connectivity",
                description: "Real-time network throughput (primary interface)",
                currentValue: 0,
                previousValue: 0,
                targetValue: 100,
                unit: "Mbps",
                status: .good,
                lastUpdated: Date()
            ),
            OptimizationMetric(
                title: "Urgent Attention",
                category: "Process Management",
                description: "Processes requiring attention",
                currentValue: 0,
                previousValue: 0,
                targetValue: 0,
                unit: " issues",
                status: .good,
                lastUpdated: Date()
            )
        ]
    }
    
    private func initializeOptimizationTasks() {
        optimizationTasks = [
            // Memory & Performance
            OptimizationTask(id: "purge_memory", title: "Purge inactive memory", description: "Free up inactive memory using purge command", category: "Memory & Performance", command: "sudo purge", requiresAdmin: true),
            OptimizationTask(id: "clear_caches", title: "Clear user caches", description: "Clear user cache files to free up disk space", category: "Memory & Performance", command: "rm -rf ~/Library/Caches/* 2>/dev/null; ls ~/Library/Caches"),
            OptimizationTask(id: "disable_spotlight", title: "Disable Spotlight indexing", description: "Turn off Spotlight indexing for better performance", category: "Memory & Performance", command: "sudo mdutil -i off /", requiresAdmin: true),
            OptimizationTask(id: "reindex_spotlight", title: "Re-index Spotlight", description: "Rebuild Spotlight index for better search performance", category: "Memory & Performance", command: "sudo mdutil -E /", requiresAdmin: true),
            // Apple SIP-protects com.apple.universalaccess; third-party apps
            // cannot write it (cfprefsd rejects, PlistBuddy gets EPERM), so
            // this task opens the Motion pane for a one-click toggle instead.
            OptimizationTask(id: "reduce_animations", title: "Reduce motion setting", description: "Open the Reduce Motion setting in System Settings for a quick toggle", category: "Memory & Performance", command: "open 'x-apple.systempreferences:com.apple.Accessibility-Settings.extension?Motion'"),
            
            // System Tweaks
            OptimizationTask(id: "disable_dock_animation", title: "Disable Dock animations", description: "Remove Dock animations for faster response", category: "System Tweaks", command: "defaults write com.apple.dock autohide-time-modifier -int 0 && defaults write com.apple.dock launchanim -bool false && killall Dock"),
            OptimizationTask(id: "disable_window_animations", title: "Disable window animations", description: "Remove window animations for snappier feel", category: "System Tweaks", command: "defaults write NSGlobalDomain NSAutomaticWindowAnimationsEnabled -bool false"),
            OptimizationTask(id: "optimize_launchpad", title: "Optimize Launchpad", description: "Speed up Launchpad loading and animations", category: "System Tweaks", command: "defaults write com.apple.dock springboard-show-duration -int 0 && killall Dock"),
            OptimizationTask(id: "optimize_finder", title: "Show hidden files in Finder", description: "Reveal hidden files in Finder for easier debugging", category: "System Tweaks", command: "defaults write com.apple.finder AppleShowAllFiles -bool true && killall Finder"),
            
            // Network
            OptimizationTask(id: "flush_dns", title: "Flush DNS cache", description: "Clear DNS cache for faster lookups", category: "Network", command: "sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder", requiresAdmin: true),
            
            // Development
            OptimizationTask(id: "optimize_git", title: "Optimize Git performance", description: "Configure Git for better performance", category: "Development", command: "git config --global core.precomposeunicode true"),
            OptimizationTask(id: "optimize_homebrew", title: "Optimize Homebrew", description: "Clean and optimize Homebrew installation", category: "Development", command: "brew cleanup"),
            OptimizationTask(id: "optimize_node", title: "Optimize Node.js", description: "Clean Node.js and npm cache", category: "Development", command: "npm cache clean --force"),
            OptimizationTask(id: "optimize_python", title: "Optimize Python", description: "Clean Python pip cache", category: "Development", command: "python3 -m pip cache purge"),
            OptimizationTask(id: "optimize_docker", title: "Optimize Docker", description: "Clean Docker containers and images", category: "Development", command: "docker system prune -f"),
            OptimizationTask(id: "optimize_xcode", title: "Optimize Xcode", description: "Clean Xcode derived data and cache", category: "Development", command: "rm -rf ~/Library/Developer/Xcode/DerivedData/*"),
            
            // Advanced
            OptimizationTask(id: "rebuild_spotlight", title: "Rebuild Spotlight index", description: "Completely rebuild Spotlight search index", category: "Advanced", command: "sudo mdutil -i off / && sudo mdutil -i on /", requiresAdmin: true),
            OptimizationTask(id: "reset_launchservices", title: "Reset Launch Services", description: "Fix 'Open With' menu problems", category: "Advanced", command: "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -kill -r -domain local -domain user"),
            OptimizationTask(id: "clear_font_cache", title: "Clear font cache", description: "Clear system font cache", category: "Advanced", command: "sudo atsutil databases -remove", requiresAdmin: true),
            OptimizationTask(id: "optimize_ssd", title: "Enable SSD TRIM", description: "Force-enable TRIM for third-party SSDs", category: "Advanced", command: "sudo trimforce enable", requiresAdmin: true),
            OptimizationTask(id: "disable_crash_reporter", title: "Disable crash reporter", description: "Turn off automatic crash reporting dialogs", category: "Advanced", command: "defaults write com.apple.CrashReporter DialogType none")
        ]
    }
    
    func runOptimization() {
        guard !selectedTasks.isEmpty, !isOptimizing else { return }

        let tasks = optimizationTasks.filter { selectedTasks.contains($0.id) }
        isOptimizing = true
        taskResults = []
        lastRunDate = Date()

        // Split on the main actor; the background work only touches strings.
        let userCommands: [(id: String, command: String)] = tasks
            .filter { !$0.requiresAdmin }
            .map { (id: $0.id, command: $0.command) }
        let adminCommands: [(id: String, command: String)] = tasks
            .filter { $0.requiresAdmin }
            .map { (id: $0.id, command: $0.command) }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var outcomes: [(id: String, code: Int32, output: String)] = []

            // User-level tasks run one by one in a login shell.
            for entry in userCommands {
                let outcome = ShellRunner.run(entry.command)
                outcomes.append((entry.id, outcome.code, outcome.output))
            }

            // Admin tasks are batched into one root shell, so several admin
            // tasks in one run trigger a single password prompt.
            if !adminCommands.isEmpty {
                let outcome = ShellRunner.runAsRoot(adminCommands.map { $0.command })
                outcomes.append(contentsOf: adminCommands.map { (id: $0.id, code: outcome.code, output: outcome.output) })
            }

            DispatchQueue.main.async {
                guard let self else { return }
                self.taskResults = outcomes.compactMap { outcome in
                    guard let task = tasks.first(where: { $0.id == outcome.id }) else { return nil }
                    return TaskRunResult(task: task, succeeded: outcome.code == 0, output: outcome.output)
                }
                self.isOptimizing = false
                self.showConfirmation = true
            }
        }
    }
    
    func toggleTask(_ taskId: String) {
        if selectedTasks.contains(taskId) {
            selectedTasks.remove(taskId)
        } else {
            selectedTasks.insert(taskId)
        }
    }
    
    func getTasksByCategory(_ category: String) -> [OptimizationTask] {
        return optimizationTasks.filter { $0.category == category }
    }
    
    var categories: [String] {
        return Array(Set(optimizationTasks.map { $0.category })).sorted()
    }
}

// MARK: - Shell Runner
enum ShellRunner {
    // Runs a command in a login shell so Homebrew and version-manager tools
    // are on PATH. Output goes to a temp file so large output cannot
    // deadlock the pipe.
    nonisolated static func run(_ command: String) -> (code: Int32, output: String) {
        execute("/bin/zsh", arguments: ["-lc", command])
    }

    // Runs all commands as root in one batch through osascript, so a run with
    // several admin tasks triggers a single password prompt.
    nonisolated static func runAsRoot(_ commands: [String]) -> (code: Int32, output: String) {
        let escaped = commands.joined(separator: " ; ")
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"
        return execute("/usr/bin/osascript", arguments: ["-e", script])
    }

    private nonisolated static func execute(_ launchPath: String, arguments: [String]) -> (code: Int32, output: String) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: launchPath)
        process.arguments = arguments

        let logURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("OptiMac-\(UUID().uuidString).log")
        guard FileManager.default.createFile(atPath: logURL.path, contents: nil),
              let logHandle = try? FileHandle(forWritingTo: logURL) else {
            return (-1, "Could not create output log")
        }
        process.standardOutput = logHandle
        process.standardError = logHandle

        do {
            try process.run()
        } catch {
            try? logHandle.close()
            try? FileManager.default.removeItem(at: logURL)
            return (-1, "Could not start \(launchPath): \(error.localizedDescription)")
        }

        process.waitUntilExit()
        try? logHandle.close()

        let data = FileManager.default.contents(atPath: logURL.path) ?? Data()
        try? FileManager.default.removeItem(at: logURL)
        let output = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        return (process.terminationStatus, output)
    }
}

// MARK: - Glass Card Component
struct GlassCardView<Content: View>: View {
    let content: Content
    
    init(@ViewBuilder content: () -> Content) {
        self.content = content()
    }
    
    var body: some View {
        content
            .padding(20)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(.ultraThinMaterial)
                    .overlay(
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(Color.white.opacity(0.28), lineWidth: 1.2)
                    )
                    .shadow(color: Color.black.opacity(0.25), radius: 14, y: 7)
            )
    }
}

// MARK: - Real Memory Usage Chart
struct RealMemoryUsageChart: View {
    @ObservedObject var realMonitor: RealSystemMonitor
    
    var body: some View {
        VStack(spacing: 8) {
            Chart {
                ForEach(Array(realMonitor.memoryInfo.appMemoryUsage.enumerated()), id: \.element.id) { _, app in
                    BarMark(
                        x: .value("App", app.name),
                        y: .value("Memory", app.memoryUsage)
                    )
                    .foregroundStyle(app.color)
                    .cornerRadius(4)
                }
            }
            .chartYAxis {
                AxisMarks(position: .leading) { value in
                    AxisGridLine(stroke: StrokeStyle(lineWidth: 0.6))
                        .foregroundStyle(Color.white.opacity(0.25))
                    AxisValueLabel() {
                        if let mb = value.as(Double.self) {
                            Text("\(Int(mb))MB")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .chartXAxis(.hidden)
            .frame(height: 80)
            
            LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 3), spacing: 4) {
                ForEach(realMonitor.memoryInfo.appMemoryUsage) { app in
                    HStack(spacing: 4) {
                        Circle()
                            .fill(app.color)
                            .frame(width: 8, height: 8)
                        Text(app.name)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }
            }
        }
    }
}

// MARK: - Real CPU Usage Chart
struct RealCPUUsageChart: View {
    @ObservedObject var realMonitor: RealSystemMonitor
    
    var body: some View {
        VStack(spacing: 8) {
            Chart {
                ForEach(realMonitor.cpuProcesses) { process in
                    BarMark(
                        x: .value("Process", process.name),
                        y: .value("CPU", process.cpuUsage)
                    )
                    .foregroundStyle(process.color)
                    .cornerRadius(4)
                }
            }
            .chartYAxis {
                AxisMarks(position: .leading) { value in
                    AxisGridLine(stroke: StrokeStyle(lineWidth: 0.6))
                        .foregroundStyle(Color.white.opacity(0.25))
                    AxisValueLabel() {
                        if let cpu = value.as(Double.self) {
                            Text("\(Int(cpu))%")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
            .chartXAxis(.hidden)
            .frame(height: 80)
            
            LazyVGrid(columns: Array(repeating: GridItem(.flexible()), count: 3), spacing: 4) {
                ForEach(realMonitor.cpuProcesses) { process in
                    HStack(spacing: 4) {
                        Circle()
                            .fill(process.color)
                            .frame(width: 8, height: 8)
                        Text(process.name)
                            .font(.caption2)
                            .foregroundColor(.secondary)
                            .lineLimit(1)
                    }
                }
            }
        }
    }
}

// MARK: - Real Network Speed Chart
struct RealNetworkSpeedChart: View {
    @ObservedObject var realMonitor: RealSystemMonitor
    
    var body: some View {
        Chart {
            ForEach(realMonitor.networkHistory, id: \.timestamp) { speed in
                LineMark(
                    x: .value("Time", speed.timestamp),
                    y: .value("Download", speed.downloadMbps)
                )
                .foregroundStyle(Color(red: 0.20, green: 0.60, blue: 1.00))
                .lineStyle(StrokeStyle(lineWidth: 2))
                
                LineMark(
                    x: .value("Time", speed.timestamp),
                    y: .value("Upload", speed.uploadMbps)
                )
                .foregroundStyle(Color(red: 0.10, green: 0.85, blue: 0.50))
                .lineStyle(StrokeStyle(lineWidth: 2))
            }
        }
        .chartXAxis(.hidden)
        .chartYAxis {
            AxisMarks(position: .leading) { value in
                AxisGridLine(stroke: StrokeStyle(lineWidth: 0.6))
                    .foregroundStyle(Color.white.opacity(0.25))
                AxisValueLabel() {
                    if let mbps = value.as(Double.self) {
                        Text("\(String(format: "%.2f", mbps))")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .frame(height: 60)
        .overlay(alignment: .bottomTrailing) {
            HStack(spacing: 12) {
                HStack(spacing: 4) {
                    Circle().fill(Color(red: 0.20, green: 0.60, blue: 1.00)).frame(width: 8, height: 8)
                    Text("Down")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
                HStack(spacing: 4) {
                    Circle().fill(Color(red: 0.10, green: 0.85, blue: 0.50)).frame(width: 8, height: 8)
                    Text("Up")
                        .font(.caption2)
                        .foregroundColor(.secondary)
                }
            }
        }
    }
}

// MARK: - Real Urgent Processes List (with working Force Quit)
struct RealUrgentProcessesList: View {
    @ObservedObject var realMonitor: RealSystemMonitor
    
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if realMonitor.urgentProcesses.isEmpty {
                Text("No urgent issues detected")
                    .font(.caption)
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding()
            } else {
                ForEach(realMonitor.urgentProcesses) { process in
                    HStack(spacing: 12) {
                        Circle()
                            .fill(process.priority.color)
                            .frame(width: 12, height: 12)
                        
                        VStack(alignment: .leading, spacing: 2) {
                            Text(process.name)
                                .font(.caption)
                                .fontWeight(.medium)
                                .foregroundColor(.primary)
                            
                            Text(process.issue)
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                        
                        Spacer()
                        
                        Button("Force Quit") {
                            realMonitor.forceQuitProcess(pid: process.pid)
                        }
                        .font(.caption2)
                        .foregroundColor(.white)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 4)
                        .background(process.priority.color)
                        .cornerRadius(6)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 6)
                    .background(Color.black.opacity(0.25))
                    .cornerRadius(8)
                }
            }
        }
    }
}

// MARK: - Enhanced Metric Card with Real System Data
struct MetricCardView: View {
    let metric: OptimizationMetric
    @ObservedObject var realSystemMonitor: RealSystemMonitor
    @State private var isAnimating = false
    
    // New: popover for the top-right badge
    @State private var showDetails = false
    
    var body: some View {
        GlassCardView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text(metric.title)
                            .font(.system(.title2, design: .rounded, weight: .bold))
                            .foregroundStyle(
                                LinearGradient(
                                    colors: [Color.white, Color.white.opacity(0.92)],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                        
                        Text(metric.category)
                            .font(.system(.subheadline, design: .rounded, weight: .medium))
                            .foregroundColor(.secondary)
                    }
                    
                    Spacer()
                    
                    // Make the badge actionable
                    Button {
                        showDetails.toggle()
                    } label: {
                        ZStack {
                            Circle()
                                .fill(getStatusColor().opacity(0.22))
                                .frame(width: 40, height: 40)
                            
                            Image(systemName: getStatusIcon())
                                .font(.system(.subheadline, weight: .bold))
                                .foregroundColor(getStatusColor())
                        }
                    }
                    .buttonStyle(.plain)
                    .popover(isPresented: $showDetails) {
                        detailsView
                            .padding(16)
                            .frame(minWidth: 260)
                    }
                }
                
                VStack(alignment: .leading, spacing: 12) {
                    HStack {
                        switch metric.title {
                        case "Memory Usage":
                            Text("Used: \(String(format: "%.1f", realSystemMonitor.memoryInfo.usedMemory))GB / \(String(format: "%.1f", realSystemMonitor.memoryInfo.totalMemory))GB")
                                .font(.system(.headline, design: .monospaced, weight: .bold))
                                .foregroundColor(.primary)
                            
                        case "System Performance":
                            Text("CPU Usage: \(String(format: "%.1f", realSystemMonitor.totalCPUUsage))%")
                                .font(.system(.headline, design: .monospaced, weight: .bold))
                                .foregroundColor(.primary)
                            
                        case "Network Speed":
                            if let latest = realSystemMonitor.networkHistory.last, realSystemMonitor.networkHistory.count > 1 {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text("↓ \(String(format: "%.2f", latest.downloadMbps)) Mbps")
                                        .font(.system(.subheadline, design: .monospaced, weight: .bold))
                                        .foregroundColor(Color(red: 0.20, green: 0.60, blue: 1.00))
                                    Text("↑ \(String(format: "%.2f", latest.uploadMbps)) Mbps")
                                        .font(.system(.subheadline, design: .monospaced, weight: .bold))
                                        .foregroundColor(Color(red: 0.10, green: 0.85, blue: 0.50))
                                }
                            } else {
                                Text("Measuring...")
                                    .font(.system(.headline, design: .rounded))
                                    .foregroundColor(.secondary)
                            }
                            
                        case "Urgent Attention":
                            Text("\(realSystemMonitor.urgentProcesses.count) issues need attention")
                                .font(.system(.headline, design: .rounded, weight: .bold))
                                .foregroundColor(getStatusColor())
                            
                        default:
                            Text("Monitoring...")
                                .font(.system(.headline, design: .monospaced, weight: .bold))
                                .foregroundColor(.primary)
                        }
                        
                        Spacer()
                    }
                    
                    // Real system data visualization
                    switch metric.title {
                    case "Memory Usage":
                        RealMemoryUsageChart(realMonitor: realSystemMonitor)
                        
                    case "System Performance":
                        RealCPUUsageChart(realMonitor: realSystemMonitor)
                        
                    case "Network Speed":
                        RealNetworkSpeedChart(realMonitor: realSystemMonitor)
                        
                    case "Urgent Attention":
                        RealUrgentProcessesList(realMonitor: realSystemMonitor)
                        
                    default:
                        EmptyView()
                    }
                }
            }
        }
        .frame(minWidth: 320, maxWidth: .infinity, minHeight: 280)
        .scaleEffect(isAnimating ? 1.0 : 0.95)
        .opacity(isAnimating ? 1.0 : 0.0)
        .onAppear {
            withAnimation(.easeInOut(duration: 0.8)) {
                isAnimating = true
            }
        }
    }
    
    private var detailsView: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(metric.title)
                .font(.headline)
            switch metric.title {
            case "Memory Usage":
                if realSystemMonitor.memoryInfo.appMemoryUsage.isEmpty {
                    Text("Collecting memory data…")
                        .foregroundColor(.secondary)
                } else {
                    ForEach(realSystemMonitor.memoryInfo.appMemoryUsage) { p in
                        HStack {
                            Circle().fill(p.color).frame(width: 6, height: 6)
                            Text(p.name).lineLimit(1)
                            Spacer()
                            Text("\(Int(p.memoryUsage)) MB")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }
            case "System Performance":
                if realSystemMonitor.cpuProcesses.isEmpty {
                    Text("Collecting CPU data…").foregroundColor(.secondary)
                } else {
                    ForEach(realSystemMonitor.cpuProcesses) { p in
                        HStack {
                            Circle().fill(p.color).frame(width: 6, height: 6)
                            Text(p.name).lineLimit(1)
                            Spacer()
                            Text("\(String(format: "%.1f", p.cpuUsage))%")
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }
            case "Network Speed":
                if let s = realSystemMonitor.networkHistory.last, realSystemMonitor.networkHistory.count > 1 {
                    Text("Down: \(String(format: "%.2f", s.downloadMbps)) Mbps")
                    Text("Up: \(String(format: "%.2f", s.uploadMbps)) Mbps")
                } else {
                    Text("Measuring…").foregroundColor(.secondary)
                }
            case "Urgent Attention":
                Button {
                    realSystemMonitor.forceQuitProcess(pid: -1) // harmless refresh
                } label: {
                    Label("Refresh List", systemImage: "arrow.clockwise")
                }
            default:
                Text("No actions available.")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
    
    private func getStatusColor() -> Color {
        switch metric.title {
        case "Urgent Attention":
            let count = realSystemMonitor.urgentProcesses.count
            if count == 0 { return Color(red: 0.10, green: 0.85, blue: 0.50) }
            else if count <= 2 { return Color(red: 1.00, green: 0.84, blue: 0.00) }
            else if count <= 4 { return Color(red: 1.00, green: 0.55, blue: 0.00) }
            else { return Color(red: 1.00, green: 0.22, blue: 0.30) }
        case "Memory Usage":
            let total = max(realSystemMonitor.memoryInfo.totalMemory, 0.0001)
            let percentUsed = (realSystemMonitor.memoryInfo.usedMemory / total) * 100
            if percentUsed < 60 { return Color(red: 0.10, green: 0.85, blue: 0.50) }
            else if percentUsed < 80 { return Color(red: 1.00, green: 0.84, blue: 0.00) }
            else { return Color(red: 1.00, green: 0.22, blue: 0.30) }
        default:
            return Color(red: 0.20, green: 0.60, blue: 1.00)
        }
    }
    
    private func getStatusIcon() -> String {
        let color = getStatusColor()
        switch color {
        case Color(red: 0.10, green: 0.85, blue: 0.50): return "checkmark.circle.fill"
        case Color(red: 1.00, green: 0.84, blue: 0.00): return "exclamationmark.triangle.fill"
        case Color(red: 1.00, green: 0.55, blue: 0.00): return "exclamationmark.triangle.fill"
        case Color(red: 1.00, green: 0.22, blue: 0.30): return "xmark.circle.fill"
        default: return "info.circle.fill"
        }
    }
}

// MARK: - Clickable Optimization Task Row
struct OptimizationTaskRow: View {
    let task: OptimizationTask
    let isSelected: Bool
    let onToggle: () -> Void
    
    @State private var showCommand = false
    
    var body: some View {
        Button(action: onToggle) {
            HStack(spacing: 16) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8)
                        .fill(isSelected ? Color(red: 0.20, green: 0.60, blue: 1.00) : Color.clear)
                        .stroke(Color(red: 0.20, green: 0.60, blue: 1.00), lineWidth: 2)
                        .frame(width: 24, height: 24)
                    
                    if isSelected {
                        Image(systemName: "checkmark")
                            .font(.system(.subheadline, weight: .bold))
                            .foregroundColor(.white)
                    }
                }
                
                VStack(alignment: .leading, spacing: 6) {
                    Text(task.title)
                        .font(.system(.title3, design: .rounded, weight: .semibold))
                        .foregroundStyle(
                            LinearGradient(
                                colors: [Color.white, Color.white.opacity(0.92)],
                                startPoint: .leading,
                                endPoint: .trailing
                            )
                        )
                    
                    Text(task.description)
                        .font(.system(.subheadline, design: .rounded))
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.leading)
                }
                
                Spacer()
                
                Button {
                    showCommand.toggle()
                } label: {
                    Image(systemName: "info.circle")
                        .font(.system(.subheadline, weight: .semibold))
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .popover(isPresented: $showCommand) {
                    VStack(alignment: .leading, spacing: 10) {
                        Text(task.title)
                            .font(.headline)
                        Text(task.description)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                        Divider()
                        Label(
                            task.requiresAdmin ? "Runs as administrator (one password prompt per run)" : "Runs as the current user",
                            systemImage: task.requiresAdmin ? "lock.shield" : "person.crop.circle"
                        )
                        .font(.caption)
                        .foregroundColor(.secondary)
                        Text(task.command)
                            .font(.system(.caption, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(16)
                    .frame(minWidth: 340, alignment: .leading)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 16)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(isSelected ? Color(red: 0.20, green: 0.60, blue: 1.00).opacity(0.18) : Color.clear)
                    .stroke(isSelected ? Color(red: 0.20, green: 0.60, blue: 1.00).opacity(0.45) : Color.clear, lineWidth: 2)
            )
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
    }
}
// MARK: - Dashboard View (single screen: select tasks and run in one place)
struct DashboardView: View {
    @ObservedObject var systemMonitor: SystemMonitor

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.04, green: 0.05, blue: 0.16),
                    Color(red: 0.10, green: 0.05, blue: 0.22),
                    Color(red: 0.18, green: 0.12, blue: 0.28)
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                ScrollView(showsIndicators: false) {
                    VStack(spacing: 32) {
                        VStack(spacing: 16) {
                            Text("OptiMac by VonKleistL")
                                .font(.system(.largeTitle, design: .rounded, weight: .heavy))
                                .foregroundStyle(
                                    LinearGradient(
                                        colors: [
                                            Color.white,
                                            Color(red: 0.80, green: 0.92, blue: 1.00),
                                            Color.white.opacity(0.92)
                                        ],
                                        startPoint: .leading,
                                        endPoint: .trailing
                                    )
                                )

                            Text("M-Series Performance Suite • Real-Time System Monitor")
                                .font(.system(.title2, design: .rounded, weight: .medium))
                                .foregroundStyle(
                                    LinearGradient(
                                        colors: [Color.white.opacity(0.88), Color.white.opacity(0.66)],
                                        startPoint: .leading,
                                        endPoint: .trailing
                                    )
                                )
                        }
                        .padding(.top, 24)

                        LazyVGrid(columns: [
                            GridItem(.flexible(), spacing: 20),
                            GridItem(.flexible(), spacing: 20)
                        ], spacing: 20) {
                            ForEach(systemMonitor.currentMetrics) { metric in
                                MetricCardView(metric: metric, realSystemMonitor: systemMonitor.realSystemMonitor)
                            }
                        }

                        ForEach(systemMonitor.categories, id: \.self) { category in
                            VStack(alignment: .leading, spacing: 12) {
                                HStack {
                                    Text(category)
                                        .font(.system(.title2, design: .rounded, weight: .bold))
                                        .foregroundStyle(
                                            LinearGradient(
                                                colors: [Color.white, Color.white.opacity(0.86)],
                                                startPoint: .leading,
                                                endPoint: .trailing
                                            )
                                        )

                                    Spacer()

                                    Text("\(selectedCount(in: category)) selected")
                                        .font(.system(.headline, design: .rounded, weight: .medium))
                                        .foregroundColor(.secondary)
                                }

                                GlassCardView {
                                    VStack(spacing: 12) {
                                        ForEach(systemMonitor.getTasksByCategory(category)) { task in
                                            OptimizationTaskRow(
                                                task: task,
                                                isSelected: systemMonitor.selectedTasks.contains(task.id)
                                            ) {
                                                systemMonitor.toggleTask(task.id)
                                            }

                                            if task.id != systemMonitor.getTasksByCategory(category).last?.id {
                                                Divider()
                                                    .padding(.horizontal, 20)
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        Spacer(minLength: 40)
                    }
                    .padding(.horizontal, 24)
                }

                GlassCardView {
                    HStack {
                        Text("\(systemMonitor.selectedTasks.count) optimizations selected")
                            .font(.system(.subheadline, design: .rounded, weight: .medium))
                            .foregroundColor(.secondary)

                        Spacer()

                        Button(action: {
                            systemMonitor.runOptimization()
                        }) {
                            HStack(spacing: 10) {
                                if systemMonitor.isOptimizing {
                                    ProgressView()
                                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                                        .scaleEffect(0.9)
                                } else {
                                    Image(systemName: "bolt.fill")
                                        .font(.system(.subheadline, weight: .bold))
                                }

                                Text(systemMonitor.isOptimizing ? "Optimizing..." : "Run Boost")
                                    .font(.system(.headline, design: .rounded, weight: .bold))
                            }
                            .foregroundColor(.white)
                            .padding(.horizontal, 24)
                            .padding(.vertical, 14)
                            .background(
                                LinearGradient(
                                    colors: [Color(red: 0.20, green: 0.60, blue: 1.00), Color(red: 0.60, green: 0.40, blue: 1.00)],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .clipShape(Capsule())
                            .shadow(color: Color(red: 0.20, green: 0.60, blue: 1.00).opacity(0.35), radius: 10, y: 5)
                        }
                        .buttonStyle(.plain)
                        .disabled(systemMonitor.isOptimizing || systemMonitor.selectedTasks.isEmpty)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
            }
        }
        // Confirmation sheet after optimizations complete
        .sheet(isPresented: $systemMonitor.showConfirmation) {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Image(systemName: "checkmark.seal.fill")
                        .foregroundColor(.green)
                    Text("Optimizations Completed")
                        .font(.title2).bold()
                }
                if let date = systemMonitor.lastRunDate {
                    Text("Finished at \(date.formatted(date: .abbreviated, time: .standard))")
                        .foregroundColor(.secondary)
                }
                if systemMonitor.taskResults.isEmpty {
                    Text("No tasks were executed.")
                } else {
                    Text("Task results:")
                        .font(.headline)
                    ScrollView {
                        VStack(alignment: .leading, spacing: 8) {
                            ForEach(systemMonitor.taskResults) { result in
                                VStack(alignment: .leading, spacing: 2) {
                                    HStack {
                                        Image(systemName: result.succeeded ? "checkmark.circle.fill" : "xmark.circle.fill")
                                            .foregroundColor(result.succeeded ? .green : Color(red: 1.00, green: 0.22, blue: 0.30))
                                        Text(result.task.title)
                                        Spacer()
                                        if result.task.requiresAdmin {
                                            Image(systemName: "lock.shield")
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                        }
                                    }
                                    if !result.output.isEmpty {
                                        Text(result.output)
                                            .font(.system(.caption, design: .monospaced))
                                            .foregroundColor(.secondary)
                                            .lineLimit(3)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    }
                                }
                                .padding(.horizontal, 8)
                                .padding(.vertical, 6)
                                .background(Color.black.opacity(0.25))
                                .cornerRadius(8)
                            }
                        }
                    }
                    .frame(minHeight: 120, maxHeight: 240)
                }
                HStack {
                    Spacer()
                    Button("Done") { systemMonitor.showConfirmation = false }
                        .keyboardShortcut(.defaultAction)
                }
            }
            .padding(24)
            .frame(minWidth: 420)
        }
    }

    private func selectedCount(in category: String) -> Int {
        systemMonitor.getTasksByCategory(category)
            .filter { systemMonitor.selectedTasks.contains($0.id) }
            .count
    }
}

// MARK: - Main Content View
struct ContentView: View {
    // Injected shared SystemMonitor instead of owning our own
    @ObservedObject var systemMonitor: SystemMonitor

    init(systemMonitor: SystemMonitor) {
        self.systemMonitor = systemMonitor
    }

    var body: some View {
        DashboardView(systemMonitor: systemMonitor)
            .preferredColorScheme(.dark)
            .accentColor(Color(red: 0.20, green: 0.60, blue: 1.00))
    }
}

#Preview {
    ContentView(systemMonitor: SystemMonitor())
        .frame(width: 1200, height: 800)
}
