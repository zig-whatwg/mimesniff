//! WHATWG MIME Type Predicates
//!
//! Spec: https://mimesniff.spec.whatwg.org/#mime-type-groups
//!
//! This module implements MIME type classification predicates as defined
//! in the WHATWG MIME Sniffing Standard §4.6 (MIME type groups).

const std = @import("std");
const mime_type = @import("mime_type.zig");
const MimeType = mime_type.MimeType;

// ============================================================================
// MIME Type Group Predicates (WHATWG MIME Sniffing §4.6)
// ============================================================================

/// Check if MIME type is an image MIME type
///
/// An image MIME type is a MIME type whose type is "image".
///
/// Spec: https://mimesniff.spec.whatwg.org/#image-mime-type
pub fn isImageMimeType(mt: *const MimeType) bool {
    return stringEqualsAscii(mt.type, "image");
}

/// Check if MIME type is an audio or video MIME type
///
/// An audio or video MIME type is any MIME type whose type is "audio" or "video",
/// or whose essence is "application/ogg".
///
/// Spec: https://mimesniff.spec.whatwg.org/#audio-or-video-mime-type
pub fn isAudioOrVideoMimeType(mt: *const MimeType) bool {
    if (stringEqualsAscii(mt.type, "audio") or stringEqualsAscii(mt.type, "video"))
        return true;

    // Check if essence is "application/ogg"
    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);
    return std.mem.eql(u8, essence, "application/ogg");
}

/// Check if MIME type is a font MIME type
///
/// A font MIME type is any MIME type whose type is "font", or whose essence
/// is one of: application/font-cff, application/font-otf, application/font-sfnt,
/// application/font-ttf, application/font-woff, application/vnd.ms-fontobject,
/// application/vnd.ms-opentype.
///
/// Spec: https://mimesniff.spec.whatwg.org/#font-mime-type
pub fn isFontMimeType(mt: *const MimeType) bool {
    if (stringEqualsAscii(mt.type, "font"))
        return true;

    // Check if essence matches font essence list
    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);

    const font_essences = [_][]const u8{
        "application/font-cff",
        "application/font-otf",
        "application/font-sfnt",
        "application/font-ttf",
        "application/font-woff",
        "application/vnd.ms-fontobject",
        "application/vnd.ms-opentype",
    };

    for (font_essences) |font_essence| {
        if (std.mem.eql(u8, essence, font_essence))
            return true;
    }

    return false;
}

/// Check if MIME type is a ZIP-based MIME type
///
/// A ZIP-based MIME type is any MIME type whose subtype ends in "+zip" or
/// whose essence is "application/zip".
///
/// Spec: https://mimesniff.spec.whatwg.org/#zip-based-mime-type
pub fn isZipBasedMimeType(mt: *const MimeType) bool {
    // Check if subtype ends with "+zip"
    const subtype_utf8 = infra.bytes.isomorphicEncode(mt.allocator, mt.subtype) catch return false;
    defer mt.allocator.free(subtype_utf8);

    if (std.mem.endsWith(u8, subtype_utf8, "+zip"))
        return true;

    // Check if essence is "application/zip"
    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);
    return std.mem.eql(u8, essence, "application/zip");
}

/// Check if MIME type is an archive MIME type
///
/// An archive MIME type is any MIME type whose essence is one of:
/// application/x-rar-compressed, application/zip, application/x-gzip.
///
/// Spec: https://mimesniff.spec.whatwg.org/#archive-mime-type
pub fn isArchiveMimeType(mt: *const MimeType) bool {
    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);

    const archive_essences = [_][]const u8{
        "application/x-rar-compressed",
        "application/zip",
        "application/x-gzip",
    };

    for (archive_essences) |archive_essence| {
        if (std.mem.eql(u8, essence, archive_essence))
            return true;
    }

    return false;
}

/// Check if MIME type is an XML MIME type
///
/// An XML MIME type is any MIME type whose subtype ends in "+xml" or whose
/// essence is "text/xml" or "application/xml".
///
/// Spec: https://mimesniff.spec.whatwg.org/#xml-mime-type
pub fn isXmlMimeType(mt: *const MimeType) bool {
    // Check if subtype ends with "+xml"
    const subtype_utf8 = infra.bytes.isomorphicEncode(mt.allocator, mt.subtype) catch return false;
    defer mt.allocator.free(subtype_utf8);

    if (std.mem.endsWith(u8, subtype_utf8, "+xml"))
        return true;

    // Check if essence is "text/xml" or "application/xml"
    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);

    return std.mem.eql(u8, essence, "text/xml") or
        std.mem.eql(u8, essence, "application/xml");
}

/// Check if MIME type is an HTML MIME type
///
/// An HTML MIME type is any MIME type whose essence is "text/html".
///
/// Spec: https://mimesniff.spec.whatwg.org/#html-mime-type
pub fn isHtmlMimeType(mt: *const MimeType) bool {
    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);
    return std.mem.eql(u8, essence, "text/html");
}

/// Check if MIME type is a scriptable MIME type
///
/// A scriptable MIME type is an XML MIME type, HTML MIME type, or any MIME type
/// whose essence is "application/pdf".
///
/// Spec: https://mimesniff.spec.whatwg.org/#scriptable-mime-type
pub fn isScriptableMimeType(mt: *const MimeType) bool {
    if (isXmlMimeType(mt) or isHtmlMimeType(mt))
        return true;

    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);
    return std.mem.eql(u8, essence, "application/pdf");
}

/// Check if MIME type is a JavaScript MIME type
///
/// A JavaScript MIME type is any MIME type whose essence is one of the
/// JavaScript MIME type essence strings.
///
/// Spec: https://mimesniff.spec.whatwg.org/#javascript-mime-type
pub fn isJavaScriptMimeType(mt: *const MimeType) bool {
    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);
    return isJavaScriptMimeTypeEssenceMatch(essence);
}

/// Check if string is a JavaScript MIME type essence match
///
/// A string is a JavaScript MIME type essence match if it is an ASCII
/// case-insensitive match for one of the JavaScript MIME type essence strings.
///
/// Spec: https://mimesniff.spec.whatwg.org/#javascript-mime-type-essence-match
pub fn isJavaScriptMimeTypeEssenceMatch(string: []const u8) bool {
    const js_essences = [_][]const u8{
        "application/ecmascript",
        "application/javascript",
        "application/x-ecmascript",
        "application/x-javascript",
        "text/ecmascript",
        "text/javascript",
        "text/javascript1.0",
        "text/javascript1.1",
        "text/javascript1.2",
        "text/javascript1.3",
        "text/javascript1.4",
        "text/javascript1.5",
        "text/jscript",
        "text/livescript",
        "text/x-ecmascript",
        "text/x-javascript",
    };

    for (js_essences) |js_essence| {
        if (std.ascii.eqlIgnoreCase(string, js_essence))
            return true;
    }

    return false;
}

/// Check if MIME type is a JSON MIME type
///
/// A JSON MIME type is any MIME type whose subtype ends in "+json" or whose
/// essence is "application/json" or "text/json".
///
/// Spec: https://mimesniff.spec.whatwg.org/#json-mime-type
pub fn isJsonMimeType(mt: *const MimeType) bool {
    // Check if subtype ends with "+json"
    const subtype_utf8 = infra.bytes.isomorphicEncode(mt.allocator, mt.subtype) catch return false;
    defer mt.allocator.free(subtype_utf8);

    if (std.mem.endsWith(u8, subtype_utf8, "+json"))
        return true;

    // Check if essence is "application/json" or "text/json"
    const essence = getEssence(mt) catch return false;
    defer mt.allocator.free(essence);

    return std.mem.eql(u8, essence, "application/json") or
        std.mem.eql(u8, essence, "text/json");
}

// ============================================================================
// Helper Functions
// ============================================================================

const infra = @import("infra");

/// Check if a UTF-16 string equals an ASCII string
fn stringEqualsAscii(utf16_str: infra.String, ascii_str: []const u8) bool {
    if (utf16_str.len != ascii_str.len) return false;

    for (utf16_str, 0..) |c, i| {
        if (c != ascii_str[i]) return false;
    }

    return true;
}

/// Get the essence of a MIME type (as UTF-8 bytes)
///
/// The essence of a MIME type is the concatenation of its type, U+002F (/),
/// and its subtype.
///
/// Spec: https://mimesniff.spec.whatwg.org/#mime-type-essence
fn getEssence(mt: *const MimeType) ![]const u8 {
    // Encode type to UTF-8
    const type_utf8 = try infra.bytes.isomorphicEncode(mt.allocator, mt.type);
    defer mt.allocator.free(type_utf8);

    // Encode subtype to UTF-8
    const subtype_utf8 = try infra.bytes.isomorphicEncode(mt.allocator, mt.subtype);
    defer mt.allocator.free(subtype_utf8);

    // Allocate: type + "/" + subtype
    const essence = try mt.allocator.alloc(u8, type_utf8.len + 1 + subtype_utf8.len);
    @memcpy(essence[0..type_utf8.len], type_utf8);
    essence[type_utf8.len] = '/';
    @memcpy(essence[type_utf8.len + 1 ..], subtype_utf8);

    return essence;
}

// ============================================================================
// Tests
// ============================================================================

test "isImageMimeType - positive" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "image/png")).?;
    defer mt.deinit();

    try std.testing.expect(isImageMimeType(&mt));
}

test "isImageMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/html")).?;
    defer mt.deinit();

    try std.testing.expect(!isImageMimeType(&mt));
}

test "isAudioOrVideoMimeType - audio" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "audio/mpeg")).?;
    defer mt.deinit();

    try std.testing.expect(isAudioOrVideoMimeType(&mt));
}

test "isAudioOrVideoMimeType - video" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "video/mp4")).?;
    defer mt.deinit();

    try std.testing.expect(isAudioOrVideoMimeType(&mt));
}

test "isAudioOrVideoMimeType - application/ogg" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/ogg")).?;
    defer mt.deinit();

    try std.testing.expect(isAudioOrVideoMimeType(&mt));
}

test "isAudioOrVideoMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/plain")).?;
    defer mt.deinit();

    try std.testing.expect(!isAudioOrVideoMimeType(&mt));
}

test "isFontMimeType - font type" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "font/woff")).?;
    defer mt.deinit();

    try std.testing.expect(isFontMimeType(&mt));
}

test "isFontMimeType - application/font-ttf" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/font-ttf")).?;
    defer mt.deinit();

    try std.testing.expect(isFontMimeType(&mt));
}

test "isFontMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/plain")).?;
    defer mt.deinit();

    try std.testing.expect(!isFontMimeType(&mt));
}

test "isZipBasedMimeType - +zip suffix" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/example+zip")).?;
    defer mt.deinit();

    try std.testing.expect(isZipBasedMimeType(&mt));
}

test "isZipBasedMimeType - application/zip" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/zip")).?;
    defer mt.deinit();

    try std.testing.expect(isZipBasedMimeType(&mt));
}

test "isZipBasedMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/x-gzip")).?;
    defer mt.deinit();

    try std.testing.expect(!isZipBasedMimeType(&mt));
}

test "isArchiveMimeType - positive cases" {
    const allocator = std.testing.allocator;

    const archives = [_][]const u8{
        "application/x-rar-compressed",
        "application/zip",
        "application/x-gzip",
    };

    for (archives) |archive| {
        var mt = (try mime_type.parseMimeType(allocator, archive)).?;
        defer mt.deinit();

        try std.testing.expect(isArchiveMimeType(&mt));
    }
}

test "isArchiveMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/plain")).?;
    defer mt.deinit();

    try std.testing.expect(!isArchiveMimeType(&mt));
}

test "isXmlMimeType - +xml suffix" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/rss+xml")).?;
    defer mt.deinit();

    try std.testing.expect(isXmlMimeType(&mt));
}

test "isXmlMimeType - text/xml" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/xml")).?;
    defer mt.deinit();

    try std.testing.expect(isXmlMimeType(&mt));
}

test "isXmlMimeType - application/xml" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/xml")).?;
    defer mt.deinit();

    try std.testing.expect(isXmlMimeType(&mt));
}

test "isXmlMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/html")).?;
    defer mt.deinit();

    try std.testing.expect(!isXmlMimeType(&mt));
}

test "isHtmlMimeType - positive" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/html")).?;
    defer mt.deinit();

    try std.testing.expect(isHtmlMimeType(&mt));
}

test "isHtmlMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/xhtml+xml")).?;
    defer mt.deinit();

    try std.testing.expect(!isHtmlMimeType(&mt));
}

test "isScriptableMimeType - HTML" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/html")).?;
    defer mt.deinit();

    try std.testing.expect(isScriptableMimeType(&mt));
}

test "isScriptableMimeType - XML" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/xml")).?;
    defer mt.deinit();

    try std.testing.expect(isScriptableMimeType(&mt));
}

test "isScriptableMimeType - PDF" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/pdf")).?;
    defer mt.deinit();

    try std.testing.expect(isScriptableMimeType(&mt));
}

test "isScriptableMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "image/png")).?;
    defer mt.deinit();

    try std.testing.expect(!isScriptableMimeType(&mt));
}

test "isJavaScriptMimeType - text/javascript" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/javascript")).?;
    defer mt.deinit();

    try std.testing.expect(isJavaScriptMimeType(&mt));
}

test "isJavaScriptMimeType - application/javascript" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/javascript")).?;
    defer mt.deinit();

    try std.testing.expect(isJavaScriptMimeType(&mt));
}

test "isJavaScriptMimeType - all variants" {
    const allocator = std.testing.allocator;

    const js_types = [_][]const u8{
        "application/ecmascript",
        "application/javascript",
        "application/x-ecmascript",
        "application/x-javascript",
        "text/ecmascript",
        "text/javascript",
        "text/javascript1.0",
        "text/javascript1.1",
        "text/javascript1.2",
        "text/javascript1.3",
        "text/javascript1.4",
        "text/javascript1.5",
        "text/jscript",
        "text/livescript",
        "text/x-ecmascript",
        "text/x-javascript",
    };

    for (js_types) |js_type| {
        var mt = (try mime_type.parseMimeType(allocator, js_type)).?;
        defer mt.deinit();

        try std.testing.expect(isJavaScriptMimeType(&mt));
    }
}

test "isJavaScriptMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/json")).?;
    defer mt.deinit();

    try std.testing.expect(!isJavaScriptMimeType(&mt));
}

test "isJavaScriptMimeTypeEssenceMatch - case insensitive" {
    try std.testing.expect(isJavaScriptMimeTypeEssenceMatch("text/javascript"));
    try std.testing.expect(isJavaScriptMimeTypeEssenceMatch("TEXT/JAVASCRIPT"));
    try std.testing.expect(isJavaScriptMimeTypeEssenceMatch("Text/JavaScript"));
}

test "isJavaScriptMimeTypeEssenceMatch - negative" {
    try std.testing.expect(!isJavaScriptMimeTypeEssenceMatch("text/plain"));
}

test "isJsonMimeType - +json suffix" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/manifest+json")).?;
    defer mt.deinit();

    try std.testing.expect(isJsonMimeType(&mt));
}

test "isJsonMimeType - application/json" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "application/json")).?;
    defer mt.deinit();

    try std.testing.expect(isJsonMimeType(&mt));
}

test "isJsonMimeType - text/json" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/json")).?;
    defer mt.deinit();

    try std.testing.expect(isJsonMimeType(&mt));
}

test "isJsonMimeType - negative" {
    const allocator = std.testing.allocator;

    var mt = (try mime_type.parseMimeType(allocator, "text/javascript")).?;
    defer mt.deinit();

    try std.testing.expect(!isJsonMimeType(&mt));
}
