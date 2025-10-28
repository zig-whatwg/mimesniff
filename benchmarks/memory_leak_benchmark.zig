//! Memory Leak Benchmark
//!
//! This benchmark runs an intense workload for over 2 minutes, creating and
//! destroying many MIME type objects, then verifies that memory returns to
//! baseline after the benchmark completes.
//!
//! Usage: zig build benchmark-memory
//!
//! The benchmark:
//! 1. Records baseline memory usage
//! 2. Runs intense operations for 2+ minutes:
//!    - Parse thousands of MIME types
//!    - Sniff thousands of resources
//!    - Create/destroy resource objects
//! 3. Forces cleanup and GC
//! 4. Checks if memory returned to baseline (within tolerance)
//!
//! Exit codes:
//!   0 = Success (no leaks detected)
//!   1 = Memory leak detected
//!   2 = Benchmark error

const std = @import("std");
const mimesniff = @import("mimesniff");

const BENCHMARK_DURATION_MS = 120_000; // 2 minutes
const MEMORY_CHECK_INTERVAL_MS = 1000; // Check every second
const LEAK_TOLERANCE_BYTES = 1024 * 1024; // 1MB tolerance for OS variance

/// Sample MIME type strings for parsing stress test
const SAMPLE_MIME_TYPES = [_][]const u8{
    "text/html",
    "text/plain",
    "text/html; charset=utf-8",
    "application/json",
    "application/json; charset=utf-8",
    "application/xml",
    "application/octet-stream",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "audio/mpeg",
    "audio/wav",
    "video/mp4",
    "video/webm",
    "application/pdf",
    "application/zip",
    "font/woff",
    "font/woff2",
    "text/css",
    "application/javascript",
    "multipart/form-data; boundary=----WebKitFormBoundary",
    "text/plain; charset=iso-8859-1",
    "application/vnd.api+json",
    "image/svg+xml",
};

/// Sample resource headers for sniffing stress test
const SAMPLE_HEADERS = [_][]const u8{
    "<!DOCTYPE html>",
    "<html><head>",
    "\x89PNG\r\n\x1a\n",
    "\xFF\xD8\xFF",
    "GIF89a",
    "RIFF\x00\x00\x00\x00WEBP",
    "\x00\x00\x00\x18ftypmp42",
    "%PDF-1.4",
    "PK\x03\x04",
    "ID3\x03\x00",
    "\x1a\x45\xDF\xA3",
    "<?xml version=\"1.0\"?>",
    "Hello, World!",
    "\x00\x01\x02\x03\x04",
    "wOFF\x00\x01\x00\x00",
    "wOF2\x00\x01\x00\x00",
    "\xFE\xFF\x00H\x00e",
    "\xFF\xFE\x48\x00\x65\x00",
    "\xEF\xBB\xBFHello",
    "OggS\x00",
};

/// Memory usage snapshot
const MemorySnapshot = struct {
    timestamp_ms: u64,
    allocated_bytes: usize,
    freed_bytes: usize,
    current_allocated: isize,
};

/// Custom allocator that tracks all allocations
const TrackingAllocator = struct {
    parent_allocator: std.mem.Allocator,
    allocated_bytes: std.atomic.Value(usize),
    freed_bytes: std.atomic.Value(usize),
    allocation_count: std.atomic.Value(usize),
    free_count: std.atomic.Value(usize),

    fn init(parent: std.mem.Allocator) TrackingAllocator {
        return .{
            .parent_allocator = parent,
            .allocated_bytes = std.atomic.Value(usize).init(0),
            .freed_bytes = std.atomic.Value(usize).init(0),
            .allocation_count = std.atomic.Value(usize).init(0),
            .free_count = std.atomic.Value(usize).init(0),
        };
    }

    fn allocator(self: *TrackingAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.parent_allocator.rawAlloc(len, ptr_align, ret_addr);
        if (result != null) {
            _ = self.allocated_bytes.fetchAdd(len, .monotonic);
            _ = self.allocation_count.fetchAdd(1, .monotonic);
        }
        return result;
    }

    fn resize(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.parent_allocator.rawResize(buf, buf_align, new_len, ret_addr);
        if (result) {
            if (new_len > buf.len) {
                _ = self.allocated_bytes.fetchAdd(new_len - buf.len, .monotonic);
            } else {
                _ = self.freed_bytes.fetchAdd(buf.len - new_len, .monotonic);
            }
        }
        return result;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        const result = self.parent_allocator.rawRemap(memory, alignment, new_len, ret_addr);
        if (result != null) {
            if (new_len > memory.len) {
                _ = self.allocated_bytes.fetchAdd(new_len - memory.len, .monotonic);
            } else {
                _ = self.freed_bytes.fetchAdd(memory.len - new_len, .monotonic);
            }
        }
        return result;
    }

    fn free(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
        const self: *TrackingAllocator = @ptrCast(@alignCast(ctx));
        _ = self.freed_bytes.fetchAdd(buf.len, .monotonic);
        _ = self.free_count.fetchAdd(1, .monotonic);
        self.parent_allocator.rawFree(buf, buf_align, ret_addr);
    }

    fn snapshot(self: *const TrackingAllocator, timestamp_ms: u64) MemorySnapshot {
        const allocated = self.allocated_bytes.load(.monotonic);
        const freed = self.freed_bytes.load(.monotonic);
        return .{
            .timestamp_ms = timestamp_ms,
            .allocated_bytes = allocated,
            .freed_bytes = freed,
            .current_allocated = @as(isize, @intCast(allocated)) - @as(isize, @intCast(freed)),
        };
    }

    fn reset(self: *TrackingAllocator) void {
        self.allocated_bytes.store(0, .monotonic);
        self.freed_bytes.store(0, .monotonic);
        self.allocation_count.store(0, .monotonic);
        self.free_count.store(0, .monotonic);
    }
};

/// Benchmark statistics
const BenchmarkStats = struct {
    operations_completed: usize,
    mime_types_parsed: usize,
    resources_sniffed: usize,
    duration_ms: u64,
    baseline_snapshot: MemorySnapshot,
    final_snapshot: MemorySnapshot,
    peak_allocated: isize,

    fn print(self: BenchmarkStats) void {
        std.debug.print("\n============================================================\n", .{});
        std.debug.print("  MEMORY LEAK BENCHMARK RESULTS\n", .{});
        std.debug.print("============================================================\n\n", .{});

        std.debug.print("Operations:\n", .{});
        std.debug.print("  Total operations:     {d:>12}\n", .{self.operations_completed});
        std.debug.print("  MIME types parsed:    {d:>12}\n", .{self.mime_types_parsed});
        std.debug.print("  Resources sniffed:    {d:>12}\n", .{self.resources_sniffed});
        std.debug.print("  Duration:             {d:>12} ms\n", .{self.duration_ms});
        std.debug.print("  Ops/sec:              {d:>12.2}\n\n", .{
            @as(f64, @floatFromInt(self.operations_completed)) / (@as(f64, @floatFromInt(self.duration_ms)) / 1000.0),
        });

        std.debug.print("Memory:\n", .{});
        std.debug.print("  Baseline allocated:   {d:>12} bytes\n", .{self.baseline_snapshot.current_allocated});
        std.debug.print("  Peak allocated:       {d:>12} bytes\n", .{self.peak_allocated});
        std.debug.print("  Final allocated:      {d:>12} bytes\n", .{self.final_snapshot.current_allocated});
        std.debug.print("  Total allocated:      {d:>12} bytes\n", .{self.final_snapshot.allocated_bytes});
        std.debug.print("  Total freed:          {d:>12} bytes\n", .{self.final_snapshot.freed_bytes});

        const leak = self.final_snapshot.current_allocated - self.baseline_snapshot.current_allocated;
        std.debug.print("  Memory delta:         {d:>12} bytes\n\n", .{leak});

        if (@abs(leak) <= LEAK_TOLERANCE_BYTES) {
            std.debug.print("PASS: No memory leak detected (within {d} byte tolerance)\n", .{LEAK_TOLERANCE_BYTES});
        } else {
            std.debug.print("FAIL: Memory leak detected! {d} bytes not freed\n", .{leak});
        }

        std.debug.print("============================================================\n\n", .{});
    }
};

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    var tracking = TrackingAllocator.init(gpa.allocator());
    const allocator = tracking.allocator();

    std.debug.print("\n============================================================\n", .{});
    std.debug.print("  MEMORY LEAK BENCHMARK\n", .{});
    std.debug.print("============================================================\n\n", .{});
    std.debug.print("Duration:        {d} seconds\n", .{BENCHMARK_DURATION_MS / 1000});
    std.debug.print("Leak tolerance:  {d} bytes\n", .{LEAK_TOLERANCE_BYTES});
    std.debug.print("Operations:      MIME parsing, resource sniffing\n", .{});
    std.debug.print("\nStarting benchmark...\n\n", .{});

    std.debug.print("[Warmup] Stabilizing allocator...\n", .{});
    {
        var i: usize = 0;
        while (i < 1000) : (i += 1) {
            const mime = try mimesniff.parseMimeType(allocator, SAMPLE_MIME_TYPES[i % SAMPLE_MIME_TYPES.len]);
            if (mime) |m| {
                var mutable = m;
                mutable.deinit();
            }
        }
    }

    // Reset tracking after warmup
    tracking.reset();

    const baseline_snapshot = tracking.snapshot(0);
    std.debug.print("[Baseline] Memory allocated: {d} bytes\n\n", .{baseline_snapshot.current_allocated});

    const start_time = std.time.milliTimestamp();
    var operations_completed: usize = 0;
    var mime_types_parsed: usize = 0;
    var resources_sniffed: usize = 0;
    var peak_allocated: isize = baseline_snapshot.current_allocated;
    var last_report = start_time;

    std.debug.print("Running benchmark (this will take 2+ minutes)...\n", .{});

    while (true) {
        const now = std.time.milliTimestamp();
        const elapsed = now - start_time;

        if (elapsed >= BENCHMARK_DURATION_MS) break;

        // Workload 1: Parse MIME types (with parameters)
        {
            const mime_str = SAMPLE_MIME_TYPES[operations_completed % SAMPLE_MIME_TYPES.len];
            const mime = try mimesniff.parseMimeType(allocator, mime_str);
            if (mime) |m| {
                var mutable = m;
                defer mutable.deinit();
                mime_types_parsed += 1;
            }
        }

        // Workload 2: Sniff resources
        {
            const header = SAMPLE_HEADERS[operations_completed % SAMPLE_HEADERS.len];
            const mime_str = SAMPLE_MIME_TYPES[operations_completed % SAMPLE_MIME_TYPES.len];

            const supplied = try mimesniff.parseMimeType(allocator, mime_str);

            var resource = mimesniff.Resource.init(allocator);
            resource.supplied_mime_type = supplied;

            const computed = try mimesniff.sniffMimeType(allocator, &resource, header);

            if (computed) |c| {
                var mutable = c;
                mutable.deinit();
            }
            resource.deinit();

            resources_sniffed += 1;
        }

        // Workload 3: Create and destroy resources with various flags
        {
            const mime_str = SAMPLE_MIME_TYPES[operations_completed % SAMPLE_MIME_TYPES.len];
            const supplied = try mimesniff.parseMimeType(allocator, mime_str);

            var resource = mimesniff.Resource.init(allocator);
            resource.supplied_mime_type = supplied;
            resource.no_sniff = (operations_completed % 2 == 0);
            resource.check_for_apache_bug = (operations_completed % 3 == 0);
            resource.deinit();
        }

        operations_completed += 1;

        // Track peak memory
        const current_snapshot = tracking.snapshot(@intCast(elapsed));
        if (current_snapshot.current_allocated > peak_allocated) {
            peak_allocated = current_snapshot.current_allocated;
        }

        if (now - last_report >= MEMORY_CHECK_INTERVAL_MS) {
            const progress = (@as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(BENCHMARK_DURATION_MS))) * 100.0;
            std.debug.print("[{d:>5}ms] Progress: {d:>5.1}% | Ops: {d:>8} | Memory: {d:>10} bytes | Peak: {d:>10} bytes\n", .{
                elapsed,
                progress,
                operations_completed,
                current_snapshot.current_allocated,
                peak_allocated,
            });
            last_report = now;
        }
    }

    const end_time = std.time.milliTimestamp();
    const duration_ms: u64 = @intCast(end_time - start_time);

    std.debug.print("\n[Complete] Benchmark finished. Performing final cleanup...\n", .{});

    std.Thread.sleep(100 * std.time.ns_per_ms);

    // Final snapshot
    const final_snapshot = tracking.snapshot(duration_ms);

    // Build stats
    const stats = BenchmarkStats{
        .operations_completed = operations_completed,
        .mime_types_parsed = mime_types_parsed,
        .resources_sniffed = resources_sniffed,
        .duration_ms = duration_ms,
        .baseline_snapshot = baseline_snapshot,
        .final_snapshot = final_snapshot,
        .peak_allocated = peak_allocated,
    };

    // Print results
    stats.print();

    // Return exit code
    const leak = final_snapshot.current_allocated - baseline_snapshot.current_allocated;
    if (@abs(leak) <= LEAK_TOLERANCE_BYTES) {
        return 0; // Success
    } else {
        return 1; // Memory leak detected
    }
}
