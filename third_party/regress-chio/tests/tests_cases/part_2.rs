
#[test]
fn run_regexp_unicode_escape() {
    test_with_configs(run_regexp_unicode_escape_tc)
}

#[rustfmt::skip]
fn run_regexp_unicode_escape_tc(tc: TestConfig) {
    // From 262 test/language/literals/regexp/u-unicode-esc.js
    tc.compilef(r#"\u{0}"#, "").test_succeeds("\u{0}");
    tc.compilef(r#"\u{1}"#, "").test_succeeds("\u{1}");
    tc.compilef(r#"\u{1}"#, "").test_fails("u");
    tc.compilef(r#"\u{3f}"#, "").test_succeeds("?");
    tc.compilef(r#"\u{000000003f}"#, "").test_succeeds("?");
    tc.compilef(r#"\u{3F}"#, "").test_succeeds("?");
    tc.compilef(r#"\u{10ffff}"#, "").test_succeeds("\u{10ffff}");
}

#[test]
fn run_regexp_unicode_property_classes() {
    test_with_configs(run_regexp_unicode_property_classes_tc)
}

#[rustfmt::skip]
fn run_regexp_unicode_property_classes_tc(tc: TestConfig) {
    // TODO: tests
    tc.compilef(r#"\p{Script=Buhid}"#, "u").test_succeeds("ᝀᝁᝂᝃᝄᝅᝆᝇᝈᝉᝊᝋᝌᝍᝎᝏᝐᝑ\u{1752}\u{1753}ᝀᝁᝂᝃᝄᝅᝆᝇᝈᝉᝊᝋᝌᝍᝎᝏᝐᝑ\u{1752}\u{1753}");
}

#[test]
fn property_escapes_invalid() {
    // From 262 test/built-ins/RegExp/property-escapes/
    test_parse_fails_flags(r#"\P{ASCII=F}"#, "u");
    test_parse_fails_flags(r#"\p{ASCII=F}"#, "u");
    test_parse_fails_flags(r#"\P{ASCII=Invalid}"#, "u");
    test_parse_fails_flags(r#"\p{ASCII=Invalid}"#, "u");
    test_parse_fails_flags(r#"\P{ASCII=N}"#, "u");
    test_parse_fails_flags(r#"\p{ASCII=N}"#, "u");
    test_parse_fails_flags(r#"\P{ASCII=No}"#, "u");
    test_parse_fails_flags(r#"\p{ASCII=No}"#, "u");
    test_parse_fails_flags(r#"\P{ASCII=T}"#, "u");
    test_parse_fails_flags(r#"\p{ASCII=T}"#, "u");
    test_parse_fails_flags(r#"\P{ASCII=Y}"#, "u");
    test_parse_fails_flags(r#"\p{ASCII=Y}"#, "u");
    test_parse_fails_flags(r#"\P{ASCII=Yes}"#, "u");
    test_parse_fails_flags(r#"\p{ASCII=Yes}"#, "u");
    test_parse_fails_flags(r#"[--\p{Hex}]"#, "u");
    test_parse_fails_flags(r#"[\uFFFF-\p{Hex}]"#, "u");
    test_parse_fails_flags(r#"[\p{Hex}-\uFFFF]"#, "u");
    test_parse_fails_flags(r#"[\p{Hex}--]"#, "u");
    test_parse_fails_flags(r#"\P{^General_Category=Letter}"#, "u");
    test_parse_fails_flags(r#"\p{^General_Category=Letter}"#, "u");
    test_parse_fails_flags(r#"[\p{}]"#, "u");
    test_parse_fails_flags(r#"[\P{}]"#, "u");
    test_parse_fails_flags(r#"\P{InAdlam}"#, "u");
    test_parse_fails_flags(r#"\p{InAdlam}"#, "u");
    test_parse_fails_flags(r#"\P{InAdlam}"#, "u");
    test_parse_fails_flags(r#"\p{InAdlam}"#, "u");
    test_parse_fails_flags(r#"\P{InScript=Adlam}"#, "u");
    test_parse_fails_flags(r#"\p{InScript=Adlam}"#, "u");
    test_parse_fails_flags(r#"[\P{invalid}]"#, "u");
    test_parse_fails_flags(r#"[\p{invalid}]"#, "u");
    test_parse_fails_flags(r#"\P{IsScript=Adlam}"#, "u");
    test_parse_fails_flags(r#"\p{IsScript=Adlam}"#, "u");
    test_parse_fails_flags(r#"\P"#, "u");
    test_parse_fails_flags(r#"\PL"#, "u");
    test_parse_fails_flags(r#"\pL"#, "u");
    test_parse_fails_flags(r#"\p"#, "u");
    test_parse_fails_flags(r#"\P{=Letter}"#, "u");
    test_parse_fails_flags(r#"\p{=Letter}"#, "u");
    test_parse_fails_flags(r#"\P{General_Category:Letter}"#, "u");
    test_parse_fails_flags(r#"\P{=}"#, "u");
    test_parse_fails_flags(r#"\p{=}"#, "u");
    test_parse_fails_flags(r#"\p{General_Category:Letter}"#, "u");
    test_parse_fails_flags(r#"\P{"#, "u");
    test_parse_fails_flags(r#"\p{"#, "u");
    test_parse_fails_flags(r#"\P}"#, "u");
    test_parse_fails_flags(r#"\p}"#, "u");
    test_parse_fails_flags(r#"\P{ General_Category=Uppercase_Letter }"#, "u");
    test_parse_fails_flags(r#"\p{ General_Category=Uppercase_Letter }"#, "u");
    test_parse_fails_flags(r#"\P{ Lowercase }"#, "u");
    test_parse_fails_flags(r#"\p{ Lowercase }"#, "u");
    test_parse_fails_flags(r#"\P{ANY}"#, "u");
    test_parse_fails_flags(r#"\p{ANY}"#, "u");
    test_parse_fails_flags(r#"\P{ASSIGNED}"#, "u");
    test_parse_fails_flags(r#"\p{ASSIGNED}"#, "u");
    test_parse_fails_flags(r#"\P{Ascii}"#, "u");
    test_parse_fails_flags(r#"\p{Ascii}"#, "u");
    test_parse_fails_flags(r#"\P{General_Category = Uppercase_Letter}"#, "u");
    test_parse_fails_flags(r#"\p{General_Category = Uppercase_Letter}"#, "u");
    test_parse_fails_flags(r#"\P{_-_lOwEr_C-A_S-E_-_}"#, "u");
    test_parse_fails_flags(r#"\p{_-_lOwEr_C-A_S-E_-_}"#, "u");
    test_parse_fails_flags(r#"\P{any}"#, "u");
    test_parse_fails_flags(r#"\p{any}"#, "u");
    test_parse_fails_flags(r#"\P{ascii}"#, "u");
    test_parse_fails_flags(r#"\p{ascii}"#, "u");
    test_parse_fails_flags(r#"\P{assigned}"#, "u");
    test_parse_fails_flags(r#"\p{assigned}"#, "u");
    test_parse_fails_flags(r#"\P{gC=uppercase_letter}"#, "u");
    test_parse_fails_flags(r#"\p{gC=uppercase_letter}"#, "u");
    test_parse_fails_flags(r#"\P{gc=uppercaseletter}"#, "u");
    test_parse_fails_flags(r#"\p{gc=uppercaseletter}"#, "u");
    test_parse_fails_flags(r#"\P{lowercase}"#, "u");
    test_parse_fails_flags(r#"\p{lowercase}"#, "u");
    test_parse_fails_flags(r#"\P{lowercase}"#, "u");
    test_parse_fails_flags(r#"\p{lowercase}"#, "u");
    test_parse_fails_flags(r#"\P{General_Category=}"#, "u");
    test_parse_fails_flags(r#"\p{General_Category=}"#, "u");
    test_parse_fails_flags(r#"\P{General_Category}"#, "u");
    test_parse_fails_flags(
        r#"\p{General_Category}","u");
    test_parse_fails_flags(r#"\P{Script_Extensions=}","u");
    test_parse_fails_flags(r#"\p{Script_Extensions=}","u");
    test_parse_fails_flags(r#"\P{Script_Extensions}","u");
    test_parse_fails_flags(r#"\p{Script_Extensions}","u");
    test_parse_fails_flags(r#"\P{Script=}","u");
    test_parse_fails_flags(r#"\p{Script=}","u");
    test_parse_fails_flags(r#"\P{Script}","u");
    test_parse_fails_flags(r#"\p{Script}","u");
    test_parse_fails_flags(r#"\P{UnknownBinaryProperty}","u");
    test_parse_fails_flags(r#"\p{UnknownBinaryProperty}","u");
    test_parse_fails_flags(r#"\P{Line_Breakz=WAT}","u");
    test_parse_fails_flags(r#"\p{Line_Breakz=WAT}","u");
    test_parse_fails_flags(r#"\P{Line_Breakz=Alphabetic}","u");
    test_parse_fails_flags(r#"\p{Line_Breakz=Alphabetic}","u");
    test_parse_fails_flags(r#"\\P{General_Category=WAT}"#,
        "u",
    );
    test_parse_fails_flags(r#"\\p{General_Category=WAT}"#, "u");
    test_parse_fails_flags(r#"\\P{Script_Extensions=H_e_h}"#, "u");
    test_parse_fails_flags(r#"\\p{Script_Extensions=H_e_h}"#, "u");
    test_parse_fails_flags(r#"\\P{Script=FooBarBazInvalid}"#, "u");
    test_parse_fails_flags(r#"\\p{Script=FooBarBazInvalid}"#, "u");
    test_parse_fails_flags(r#"\P{Composition_Exclusion}"#, "u");
    test_parse_fails_flags(r#"\p{Composition_Exclusion}"#, "u");
    test_parse_fails_flags(r#"\P{Expands_On_NFC}"#, "u");
    test_parse_fails_flags(r#"\p{Expands_On_NFC}"#, "u");
    test_parse_fails_flags(r#"\P{Expands_On_NFD}"#, "u");
    test_parse_fails_flags(r#"\p{Expands_On_NFD}"#, "u");
    test_parse_fails_flags(r#"\P{Expands_On_NFKC}"#, "u");
    test_parse_fails_flags(r#"\p{Expands_On_NFKC}"#, "u");
    test_parse_fails_flags(r#"\P{Expands_On_NFKD}"#, "u");
    test_parse_fails_flags(r#"\p{Expands_On_NFKD}"#, "u");
    test_parse_fails_flags(r#"\P{FC_NFKC_Closure}"#, "u");
    test_parse_fails_flags(r#"\p{FC_NFKC_Closure}"#, "u");
    test_parse_fails_flags(r#"\P{Full_Composition_Exclusion}"#, "u");
    test_parse_fails_flags(r#"\p{Full_Composition_Exclusion}"#, "u");
    test_parse_fails_flags(r#"\P{Grapheme_Link}"#, "u");
    test_parse_fails_flags(r#"\p{Grapheme_Link}"#, "u");
    test_parse_fails_flags(r#"\P{Hyphen}"#, "u");
    test_parse_fails_flags(r#"\p{Hyphen}"#, "u");
    test_parse_fails_flags(r#"\P{Other_Alphabetic}"#, "u");
    test_parse_fails_flags(r#"\p{Other_Alphabetic}"#, "u");
    test_parse_fails_flags(r#"\P{Other_Default_Ignorable_Code_Point}"#, "u");
    test_parse_fails_flags(r#"\p{Other_Default_Ignorable_Code_Point}"#, "u");
    test_parse_fails_flags(r#"\P{Other_Grapheme_Extend}"#, "u");
    test_parse_fails_flags(r#"\p{Other_Grapheme_Extend}"#, "u");
    test_parse_fails_flags(r#"\P{Other_ID_Continue}"#, "u");
    test_parse_fails_flags(r#"\p{Other_ID_Continue}"#, "u");
    test_parse_fails_flags(r#"\P{Other_ID_Start}"#, "u");
    test_parse_fails_flags(r#"\p{Other_ID_Start}"#, "u");
    test_parse_fails_flags(r#"\P{Other_Lowercase}"#, "u");
    test_parse_fails_flags(r#"\p{Other_Lowercase}"#, "u");
    test_parse_fails_flags(r#"\P{Other_Math}"#, "u");
    test_parse_fails_flags(r#"\p{Other_Math}"#, "u");
    test_parse_fails_flags(r#"\P{Other_Uppercase}"#, "u");
    test_parse_fails_flags(r#"\p{Other_Uppercase}"#, "u");
    test_parse_fails_flags(r#"\P{Prepended_Concatenation_Mark}"#, "u");
    test_parse_fails_flags(r#"\p{Prepended_Concatenation_Mark}"#, "u");
    test_parse_fails_flags(r#"\P{Block=Adlam}"#, "u");
    test_parse_fails_flags(r#"\p{Block=Adlam}"#, "u");
    test_parse_fails_flags(r#"\P{FC_NFKC_Closure}"#, "u");
    test_parse_fails_flags(r#"\p{FC_NFKC_Closure}"#, "u");
    test_parse_fails_flags(r#"\P{Line_Break=Alphabetic}"#, "u");
    test_parse_fails_flags(r#"\P{Line_Break=Alphabetic}"#, "u");
    test_parse_fails_flags(r#"\p{Line_Break=Alphabetic}"#, "u");
    test_parse_fails_flags(r#"\p{Line_Break}"#, "u");
}

#[test]
fn unicode_escape_property_binary_ascii() {
    test_with_configs(unicode_escape_property_binary_ascii_tc)
}

fn unicode_escape_property_binary_ascii_tc(tc: TestConfig) {
    const CODE_POINTS: [&str; 7] = [
        "\u{0}", "\u{A}", "\u{17}", "\u{2A}", "\u{3C}", "\u{63}", "\u{7F}",
    ];
    const REGEXES: [&str; 1] = ["^\\p{ASCII}+$"];
    for regex in REGEXES {
        let regex = tc.compilef(regex, "u");
        for code_point in CODE_POINTS {
            regex.test_succeeds(code_point);
        }
    }
}

#[test]
fn unicode_escape_property_binary_any() {
    test_with_configs(unicode_escape_property_binary_any_tc)
}

fn unicode_escape_property_binary_any_tc(tc: TestConfig) {
    const CODE_POINTS: [&str; 7] = [
        "\u{0}",
        "\u{F}",
        "\u{FF}",
        "\u{FFF}",
        "\u{FFFF}",
        "\u{FFFFF}",
        "\u{10FFFF}",
    ];
    const REGEXES: [&str; 1] = ["^\\p{Any}+$"];
    for regex in REGEXES {
        let regex = tc.compilef(regex, "u");
        for code_point in CODE_POINTS {
            regex.test_succeeds(code_point);
        }
    }
}

#[test]
fn unicode_escape_property_binary_assigned() {
    test_with_configs(unicode_escape_property_binary_assigned_tc)
}

fn unicode_escape_property_binary_assigned_tc(tc: TestConfig) {
    const CODE_POINTS: [&str; 6] = [
        "\u{377}",
        "\u{c69}",
        "\u{2d96}",
        "\u{11a47}",
        "\u{1d51c}",
        "\u{10fffd}",
    ];
    const REGEXES: [&str; 1] = ["^\\p{Assigned}+$"];
    for regex in REGEXES {
        let regex = tc.compilef(regex, "u");
        for code_point in CODE_POINTS {
            regex.test_succeeds(code_point);
        }
    }
}

#[test]
fn unicode_escape_id_start() {
    test_with_configs(unicode_escape_id_start_tc)
}

fn unicode_escape_id_start_tc(tc: TestConfig) {
    const CODE_POINTS: [&str; 5] = ["A", "ꬦ", "ꫪ", "ꩂ", "ᮠ"];
    const REGEXES: [&str; 1] = [
        // `/\p{ID_Start}/u`
        r"(?:[A-Za-z\xAA\xB5\xBA\xC0-\xD6\xD8-\xF6\xF8-\u02C1\u02C6-\u02D1\u02E0-\u02E4\u02EC\u02EE\u0370-\u0374\u0376\u0377\u037A-\u037D\u037F\u0386\u0388-\u038A\u038C\u038E-\u03A1\u03A3-\u03F5\u03F7-\u0481\u048A-\u052F\u0531-\u0556\u0559\u0560-\u0588\u05D0-\u05EA\u05EF-\u05F2\u0620-\u064A\u066E\u066F\u0671-\u06D3\u06D5\u06E5\u06E6\u06EE\u06EF\u06FA-\u06FC\u06FF\u0710\u0712-\u072F\u074D-\u07A5\u07B1\u07CA-\u07EA\u07F4\u07F5\u07FA\u0800-\u0815\u081A\u0824\u0828\u0840-\u0858\u0860-\u086A\u08A0-\u08B4\u08B6-\u08C7\u0904-\u0939\u093D\u0950\u0958-\u0961\u0971-\u0980\u0985-\u098C\u098F\u0990\u0993-\u09A8\u09AA-\u09B0\u09B2\u09B6-\u09B9\u09BD\u09CE\u09DC\u09DD\u09DF-\u09E1\u09F0\u09F1\u09FC\u0A05-\u0A0A\u0A0F\u0A10\u0A13-\u0A28\u0A2A-\u0A30\u0A32\u0A33\u0A35\u0A36\u0A38\u0A39\u0A59-\u0A5C\u0A5E\u0A72-\u0A74\u0A85-\u0A8D\u0A8F-\u0A91\u0A93-\u0AA8\u0AAA-\u0AB0\u0AB2\u0AB3\u0AB5-\u0AB9\u0ABD\u0AD0\u0AE0\u0AE1\u0AF9\u0B05-\u0B0C\u0B0F\u0B10\u0B13-\u0B28\u0B2A-\u0B30\u0B32\u0B33\u0B35-\u0B39\u0B3D\u0B5C\u0B5D\u0B5F-\u0B61\u0B71\u0B83\u0B85-\u0B8A\u0B8E-\u0B90\u0B92-\u0B95\u0B99\u0B9A\u0B9C\u0B9E\u0B9F\u0BA3\u0BA4\u0BA8-\u0BAA\u0BAE-\u0BB9\u0BD0\u0C05-\u0C0C\u0C0E-\u0C10\u0C12-\u0C28\u0C2A-\u0C39\u0C3D\u0C58-\u0C5A\u0C60\u0C61\u0C80\u0C85-\u0C8C\u0C8E-\u0C90\u0C92-\u0CA8\u0CAA-\u0CB3\u0CB5-\u0CB9\u0CBD\u0CDE\u0CE0\u0CE1\u0CF1\u0CF2\u0D04-\u0D0C\u0D0E-\u0D10\u0D12-\u0D3A\u0D3D\u0D4E\u0D54-\u0D56\u0D5F-\u0D61\u0D7A-\u0D7F\u0D85-\u0D96\u0D9A-\u0DB1\u0DB3-\u0DBB\u0DBD\u0DC0-\u0DC6\u0E01-\u0E30\u0E32\u0E33\u0E40-\u0E46\u0E81\u0E82\u0E84\u0E86-\u0E8A\u0E8C-\u0EA3\u0EA5\u0EA7-\u0EB0\u0EB2\u0EB3\u0EBD\u0EC0-\u0EC4\u0EC6\u0EDC-\u0EDF\u0F00\u0F40-\u0F47\u0F49-\u0F6C\u0F88-\u0F8C\u1000-\u102A\u103F\u1050-\u1055\u105A-\u105D\u1061\u1065\u1066\u106E-\u1070\u1075-\u1081\u108E\u10A0-\u10C5\u10C7\u10CD\u10D0-\u10FA\u10FC-\u1248\u124A-\u124D\u1250-\u1256\u1258\u125A-\u125D\u1260-\u1288\u128A-\u128D\u1290-\u12B0\u12B2-\u12B5\u12B8-\u12BE\u12C0\u12C2-\u12C5\u12C8-\u12D6\u12D8-\u1310\u1312-\u1315\u1318-\u135A\u1380-\u138F\u13A0-\u13F5\u13F8-\u13FD\u1401-\u166C\u166F-\u167F\u1681-\u169A\u16A0-\u16EA\u16EE-\u16F8\u1700-\u170C\u170E-\u1711\u1720-\u1731\u1740-\u1751\u1760-\u176C\u176E-\u1770\u1780-\u17B3\u17D7\u17DC\u1820-\u1878\u1880-\u18A8\u18AA\u18B0-\u18F5\u1900-\u191E\u1950-\u196D\u1970-\u1974\u1980-\u19AB\u19B0-\u19C9\u1A00-\u1A16\u1A20-\u1A54\u1AA7\u1B05-\u1B33\u1B45-\u1B4B\u1B83-\u1BA0\u1BAE\u1BAF\u1BBA-\u1BE5\u1C00-\u1C23\u1C4D-\u1C4F\u1C5A-\u1C7D\u1C80-\u1C88\u1C90-\u1CBA\u1CBD-\u1CBF\u1CE9-\u1CEC\u1CEE-\u1CF3\u1CF5\u1CF6\u1CFA\u1D00-\u1DBF\u1E00-\u1F15\u1F18-\u1F1D\u1F20-\u1F45\u1F48-\u1F4D\u1F50-\u1F57\u1F59\u1F5B\u1F5D\u1F5F-\u1F7D\u1F80-\u1FB4\u1FB6-\u1FBC\u1FBE\u1FC2-\u1FC4\u1FC6-\u1FCC\u1FD0-\u1FD3\u1FD6-\u1FDB\u1FE0-\u1FEC\u1FF2-\u1FF4\u1FF6-\u1FFC\u2071\u207F\u2090-\u209C\u2102\u2107\u210A-\u2113\u2115\u2118-\u211D\u2124\u2126\u2128\u212A-\u2139\u213C-\u213F\u2145-\u2149\u214E\u2160-\u2188\u2C00-\u2C2E\u2C30-\u2C5E\u2C60-\u2CE4\u2CEB-\u2CEE\u2CF2\u2CF3\u2D00-\u2D25\u2D27\u2D2D\u2D30-\u2D67\u2D6F\u2D80-\u2D96\u2DA0-\u2DA6\u2DA8-\u2DAE\u2DB0-\u2DB6\u2DB8-\u2DBE\u2DC0-\u2DC6\u2DC8-\u2DCE\u2DD0-\u2DD6\u2DD8-\u2DDE\u3005-\u3007\u3021-\u3029\u3031-\u3035\u3038-\u303C\u3041-\u3096\u309B-\u309F\u30A1-\u30FA\u30FC-\u30FF\u3105-\u312F\u3131-\u318E\u31A0-\u31BF\u31F0-\u31FF\u3400-\u4DBF\u4E00-\u9FFC\uA000-\uA48C\uA4D0-\uA4FD\uA500-\uA60C\uA610-\uA61F\uA62A\uA62B\uA640-\uA66E\uA67F-\uA69D\uA6A0-\uA6EF\uA717-\uA71F\uA722-\uA788\uA78B-\uA7BF\uA7C2-\uA7CA\uA7F5-\uA801\uA803-\uA805\uA807-\uA80A\uA80C-\uA822\uA840-\uA873\uA882-\uA8B3\uA8F2-\uA8F7\uA8FB\uA8FD\uA8FE\uA90A-\uA925\uA930-\uA946\uA960-\uA97C\uA984-\uA9B2\uA9CF\uA9E0-\uA9E4\uA9E6-\uA9EF\uA9FA-\uA9FE\uAA00-\uAA28\uAA40-\uAA42\uAA44-\uAA4B\uAA60-\uAA76\uAA7A\uAA7E-\uAAAF\uAAB1\uAAB5\uAAB6\uAAB9-\uAABD\uAAC0\uAAC2\uAADB-\uAADD\uAAE0-\uAAEA\uAAF2-\uAAF4\uAB01-\uAB06\uAB09-\uAB0E\uAB11-\uAB16\uAB20-\uAB26\uAB28-\uAB2E\uAB30-\uAB5A\uAB5C-\uAB69\uAB70-\uABE2\uAC00-\uD7A3\uD7B0-\uD7C6\uD7CB-\uD7FB\uF900-\uFA6D\uFA70-\uFAD9\uFB00-\uFB06\uFB13-\uFB17\uFB1D\uFB1F-\uFB28\uFB2A-\uFB36\uFB38-\uFB3C\uFB3E\uFB40\uFB41\uFB43\uFB44\uFB46-\uFBB1\uFBD3-\uFD3D\uFD50-\uFD8F\uFD92-\uFDC7\uFDF0-\uFDFB\uFE70-\uFE74\uFE76-\uFEFC\uFF21-\uFF3A\uFF41-\uFF5A\uFF66-\uFFBE\uFFC2-\uFFC7\uFFCA-\uFFCF\uFFD2-\uFFD7\uFFDA-\uFFDC]|\uD800[\uDC00-\uDC0B\uDC0D-\uDC26\uDC28-\uDC3A\uDC3C\uDC3D\uDC3F-\uDC4D\uDC50-\uDC5D\uDC80-\uDCFA\uDD40-\uDD74\uDE80-\uDE9C\uDEA0-\uDED0\uDF00-\uDF1F\uDF2D-\uDF4A\uDF50-\uDF75\uDF80-\uDF9D\uDFA0-\uDFC3\uDFC8-\uDFCF\uDFD1-\uDFD5]|\uD801[\uDC00-\uDC9D\uDCB0-\uDCD3\uDCD8-\uDCFB\uDD00-\uDD27\uDD30-\uDD63\uDE00-\uDF36\uDF40-\uDF55\uDF60-\uDF67]|\uD802[\uDC00-\uDC05\uDC08\uDC0A-\uDC35\uDC37\uDC38\uDC3C\uDC3F-\uDC55\uDC60-\uDC76\uDC80-\uDC9E\uDCE0-\uDCF2\uDCF4\uDCF5\uDD00-\uDD15\uDD20-\uDD39\uDD80-\uDDB7\uDDBE\uDDBF\uDE00\uDE10-\uDE13\uDE15-\uDE17\uDE19-\uDE35\uDE60-\uDE7C\uDE80-\uDE9C\uDEC0-\uDEC7\uDEC9-\uDEE4\uDF00-\uDF35\uDF40-\uDF55\uDF60-\uDF72\uDF80-\uDF91]|\uD803[\uDC00-\uDC48\uDC80-\uDCB2\uDCC0-\uDCF2\uDD00-\uDD23\uDE80-\uDEA9\uDEB0\uDEB1\uDF00-\uDF1C\uDF27\uDF30-\uDF45\uDFB0-\uDFC4\uDFE0-\uDFF6]|\uD804[\uDC03-\uDC37\uDC83-\uDCAF\uDCD0-\uDCE8\uDD03-\uDD26\uDD44\uDD47\uDD50-\uDD72\uDD76\uDD83-\uDDB2\uDDC1-\uDDC4\uDDDA\uDDDC\uDE00-\uDE11\uDE13-\uDE2B\uDE80-\uDE86\uDE88\uDE8A-\uDE8D\uDE8F-\uDE9D\uDE9F-\uDEA8\uDEB0-\uDEDE\uDF05-\uDF0C\uDF0F\uDF10\uDF13-\uDF28\uDF2A-\uDF30\uDF32\uDF33\uDF35-\uDF39\uDF3D\uDF50\uDF5D-\uDF61]|\uD805[\uDC00-\uDC34\uDC47-\uDC4A\uDC5F-\uDC61\uDC80-\uDCAF\uDCC4\uDCC5\uDCC7\uDD80-\uDDAE\uDDD8-\uDDDB\uDE00-\uDE2F\uDE44\uDE80-\uDEAA\uDEB8\uDF00-\uDF1A]|\uD806[\uDC00-\uDC2B\uDCA0-\uDCDF\uDCFF-\uDD06\uDD09\uDD0C-\uDD13\uDD15\uDD16\uDD18-\uDD2F\uDD3F\uDD41\uDDA0-\uDDA7\uDDAA-\uDDD0\uDDE1\uDDE3\uDE00\uDE0B-\uDE32\uDE3A\uDE50\uDE5C-\uDE89\uDE9D\uDEC0-\uDEF8]|\uD807[\uDC00-\uDC08\uDC0A-\uDC2E\uDC40\uDC72-\uDC8F\uDD00-\uDD06\uDD08\uDD09\uDD0B-\uDD30\uDD46\uDD60-\uDD65\uDD67\uDD68\uDD6A-\uDD89\uDD98\uDEE0-\uDEF2\uDFB0]|\uD808[\uDC00-\uDF99]|\uD809[\uDC00-\uDC6E\uDC80-\uDD43]|[\uD80C\uD81C-\uD820\uD822\uD840-\uD868\uD86A-\uD86C\uD86F-\uD872\uD874-\uD879\uD880-\uD883][\uDC00-\uDFFF]|\uD80D[\uDC00-\uDC2E]|\uD811[\uDC00-\uDE46]|\uD81A[\uDC00-\uDE38\uDE40-\uDE5E\uDED0-\uDEED\uDF00-\uDF2F\uDF40-\uDF43\uDF63-\uDF77\uDF7D-\uDF8F]|\uD81B[\uDE40-\uDE7F\uDF00-\uDF4A\uDF50\uDF93-\uDF9F\uDFE0\uDFE1\uDFE3]|\uD821[\uDC00-\uDFF7]|\uD823[\uDC00-\uDCD5\uDD00-\uDD08]|\uD82C[\uDC00-\uDD1E\uDD50-\uDD52\uDD64-\uDD67\uDD70-\uDEFB]|\uD82F[\uDC00-\uDC6A\uDC70-\uDC7C\uDC80-\uDC88\uDC90-\uDC99]|\uD835[\uDC00-\uDC54\uDC56-\uDC9C\uDC9E\uDC9F\uDCA2\uDCA5\uDCA6\uDCA9-\uDCAC\uDCAE-\uDCB9\uDCBB\uDCBD-\uDCC3\uDCC5-\uDD05\uDD07-\uDD0A\uDD0D-\uDD14\uDD16-\uDD1C\uDD1E-\uDD39\uDD3B-\uDD3E\uDD40-\uDD44\uDD46\uDD4A-\uDD50\uDD52-\uDEA5\uDEA8-\uDEC0\uDEC2-\uDEDA\uDEDC-\uDEFA\uDEFC-\uDF14\uDF16-\uDF34\uDF36-\uDF4E\uDF50-\uDF6E\uDF70-\uDF88\uDF8A-\uDFA8\uDFAA-\uDFC2\uDFC4-\uDFCB]|\uD838[\uDD00-\uDD2C\uDD37-\uDD3D\uDD4E\uDEC0-\uDEEB]|\uD83A[\uDC00-\uDCC4\uDD00-\uDD43\uDD4B]|\uD83B[\uDE00-\uDE03\uDE05-\uDE1F\uDE21\uDE22\uDE24\uDE27\uDE29-\uDE32\uDE34-\uDE37\uDE39\uDE3B\uDE42\uDE47\uDE49\uDE4B\uDE4D-\uDE4F\uDE51\uDE52\uDE54\uDE57\uDE59\uDE5B\uDE5D\uDE5F\uDE61\uDE62\uDE64\uDE67-\uDE6A\uDE6C-\uDE72\uDE74-\uDE77\uDE79-\uDE7C\uDE7E\uDE80-\uDE89\uDE8B-\uDE9B\uDEA1-\uDEA3\uDEA5-\uDEA9\uDEAB-\uDEBB]|\uD869[\uDC00-\uDEDD\uDF00-\uDFFF]|\uD86D[\uDC00-\uDF34\uDF40-\uDFFF]|\uD86E[\uDC00-\uDC1D\uDC20-\uDFFF]|\uD873[\uDC00-\uDEA1\uDEB0-\uDFFF]|\uD87A[\uDC00-\uDFE0]|\uD87E[\uDC00-\uDE1D]|\uD884[\uDC00-\uDF4A])",
    ];

    for regex in REGEXES {
        let regex = tc.compile(regex);
        for code_point in CODE_POINTS {
            regex.test_succeeds(code_point);
        }
    }
}

#[test]
fn unicode_escape_id_continue() {
    test_with_configs(unicode_escape_id_continue_tc)
}

fn unicode_escape_id_continue_tc(tc: TestConfig) {
    const CODE_POINTS: [&str; 5] = ["9", "꯵", "᧖", "႗", "႙"];
    const REGEXES: [&str; 1] = [
        // `/\p{ID_Continue}/u`
        r"(?:[0-9A-Z_a-z\xAA\xB5\xB7\xBA\xC0-\xD6\xD8-\xF6\xF8-\u02C1\u02C6-\u02D1\u02E0-\u02E4\u02EC\u02EE\u0300-\u0374\u0376\u0377\u037A-\u037D\u037F\u0386-\u038A\u038C\u038E-\u03A1\u03A3-\u03F5\u03F7-\u0481\u0483-\u0487\u048A-\u052F\u0531-\u0556\u0559\u0560-\u0588\u0591-\u05BD\u05BF\u05C1\u05C2\u05C4\u05C5\u05C7\u05D0-\u05EA\u05EF-\u05F2\u0610-\u061A\u0620-\u0669\u066E-\u06D3\u06D5-\u06DC\u06DF-\u06E8\u06EA-\u06FC\u06FF\u0710-\u074A\u074D-\u07B1\u07C0-\u07F5\u07FA\u07FD\u0800-\u082D\u0840-\u085B\u0860-\u086A\u08A0-\u08B4\u08B6-\u08C7\u08D3-\u08E1\u08E3-\u0963\u0966-\u096F\u0971-\u0983\u0985-\u098C\u098F\u0990\u0993-\u09A8\u09AA-\u09B0\u09B2\u09B6-\u09B9\u09BC-\u09C4\u09C7\u09C8\u09CB-\u09CE\u09D7\u09DC\u09DD\u09DF-\u09E3\u09E6-\u09F1\u09FC\u09FE\u0A01-\u0A03\u0A05-\u0A0A\u0A0F\u0A10\u0A13-\u0A28\u0A2A-\u0A30\u0A32\u0A33\u0A35\u0A36\u0A38\u0A39\u0A3C\u0A3E-\u0A42\u0A47\u0A48\u0A4B-\u0A4D\u0A51\u0A59-\u0A5C\u0A5E\u0A66-\u0A75\u0A81-\u0A83\u0A85-\u0A8D\u0A8F-\u0A91\u0A93-\u0AA8\u0AAA-\u0AB0\u0AB2\u0AB3\u0AB5-\u0AB9\u0ABC-\u0AC5\u0AC7-\u0AC9\u0ACB-\u0ACD\u0AD0\u0AE0-\u0AE3\u0AE6-\u0AEF\u0AF9-\u0AFF\u0B01-\u0B03\u0B05-\u0B0C\u0B0F\u0B10\u0B13-\u0B28\u0B2A-\u0B30\u0B32\u0B33\u0B35-\u0B39\u0B3C-\u0B44\u0B47\u0B48\u0B4B-\u0B4D\u0B55-\u0B57\u0B5C\u0B5D\u0B5F-\u0B63\u0B66-\u0B6F\u0B71\u0B82\u0B83\u0B85-\u0B8A\u0B8E-\u0B90\u0B92-\u0B95\u0B99\u0B9A\u0B9C\u0B9E\u0B9F\u0BA3\u0BA4\u0BA8-\u0BAA\u0BAE-\u0BB9\u0BBE-\u0BC2\u0BC6-\u0BC8\u0BCA-\u0BCD\u0BD0\u0BD7\u0BE6-\u0BEF\u0C00-\u0C0C\u0C0E-\u0C10\u0C12-\u0C28\u0C2A-\u0C39\u0C3D-\u0C44\u0C46-\u0C48\u0C4A-\u0C4D\u0C55\u0C56\u0C58-\u0C5A\u0C60-\u0C63\u0C66-\u0C6F\u0C80-\u0C83\u0C85-\u0C8C\u0C8E-\u0C90\u0C92-\u0CA8\u0CAA-\u0CB3\u0CB5-\u0CB9\u0CBC-\u0CC4\u0CC6-\u0CC8\u0CCA-\u0CCD\u0CD5\u0CD6\u0CDE\u0CE0-\u0CE3\u0CE6-\u0CEF\u0CF1\u0CF2\u0D00-\u0D0C\u0D0E-\u0D10\u0D12-\u0D44\u0D46-\u0D48\u0D4A-\u0D4E\u0D54-\u0D57\u0D5F-\u0D63\u0D66-\u0D6F\u0D7A-\u0D7F\u0D81-\u0D83\u0D85-\u0D96\u0D9A-\u0DB1\u0DB3-\u0DBB\u0DBD\u0DC0-\u0DC6\u0DCA\u0DCF-\u0DD4\u0DD6\u0DD8-\u0DDF\u0DE6-\u0DEF\u0DF2\u0DF3\u0E01-\u0E3A\u0E40-\u0E4E\u0E50-\u0E59\u0E81\u0E82\u0E84\u0E86-\u0E8A\u0E8C-\u0EA3\u0EA5\u0EA7-\u0EBD\u0EC0-\u0EC4\u0EC6\u0EC8-\u0ECD\u0ED0-\u0ED9\u0EDC-\u0EDF\u0F00\u0F18\u0F19\u0F20-\u0F29\u0F35\u0F37\u0F39\u0F3E-\u0F47\u0F49-\u0F6C\u0F71-\u0F84\u0F86-\u0F97\u0F99-\u0FBC\u0FC6\u1000-\u1049\u1050-\u109D\u10A0-\u10C5\u10C7\u10CD\u10D0-\u10FA\u10FC-\u1248\u124A-\u124D\u1250-\u1256\u1258\u125A-\u125D\u1260-\u1288\u128A-\u128D\u1290-\u12B0\u12B2-\u12B5\u12B8-\u12BE\u12C0\u12C2-\u12C5\u12C8-\u12D6\u12D8-\u1310\u1312-\u1315\u1318-\u135A\u135D-\u135F\u1369-\u1371\u1380-\u138F\u13A0-\u13F5\u13F8-\u13FD\u1401-\u166C\u166F-\u167F\u1681-\u169A\u16A0-\u16EA\u16EE-\u16F8\u1700-\u170C\u170E-\u1714\u1720-\u1734\u1740-\u1753\u1760-\u176C\u176E-\u1770\u1772\u1773\u1780-\u17D3\u17D7\u17DC\u17DD\u17E0-\u17E9\u180B-\u180D\u1810-\u1819\u1820-\u1878\u1880-\u18AA\u18B0-\u18F5\u1900-\u191E\u1920-\u192B\u1930-\u193B\u1946-\u196D\u1970-\u1974\u1980-\u19AB\u19B0-\u19C9\u19D0-\u19DA\u1A00-\u1A1B\u1A20-\u1A5E\u1A60-\u1A7C\u1A7F-\u1A89\u1A90-\u1A99\u1AA7\u1AB0-\u1ABD\u1ABF\u1AC0\u1B00-\u1B4B\u1B50-\u1B59\u1B6B-\u1B73\u1B80-\u1BF3\u1C00-\u1C37\u1C40-\u1C49\u1C4D-\u1C7D\u1C80-\u1C88\u1C90-\u1CBA\u1CBD-\u1CBF\u1CD0-\u1CD2\u1CD4-\u1CFA\u1D00-\u1DF9\u1DFB-\u1F15\u1F18-\u1F1D\u1F20-\u1F45\u1F48-\u1F4D\u1F50-\u1F57\u1F59\u1F5B\u1F5D\u1F5F-\u1F7D\u1F80-\u1FB4\u1FB6-\u1FBC\u1FBE\u1FC2-\u1FC4\u1FC6-\u1FCC\u1FD0-\u1FD3\u1FD6-\u1FDB\u1FE0-\u1FEC\u1FF2-\u1FF4\u1FF6-\u1FFC\u203F\u2040\u2054\u2071\u207F\u2090-\u209C\u20D0-\u20DC\u20E1\u20E5-\u20F0\u2102\u2107\u210A-\u2113\u2115\u2118-\u211D\u2124\u2126\u2128\u212A-\u2139\u213C-\u213F\u2145-\u2149\u214E\u2160-\u2188\u2C00-\u2C2E\u2C30-\u2C5E\u2C60-\u2CE4\u2CEB-\u2CF3\u2D00-\u2D25\u2D27\u2D2D\u2D30-\u2D67\u2D6F\u2D7F-\u2D96\u2DA0-\u2DA6\u2DA8-\u2DAE\u2DB0-\u2DB6\u2DB8-\u2DBE\u2DC0-\u2DC6\u2DC8-\u2DCE\u2DD0-\u2DD6\u2DD8-\u2DDE\u2DE0-\u2DFF\u3005-\u3007\u3021-\u302F\u3031-\u3035\u3038-\u303C\u3041-\u3096\u3099-\u309F\u30A1-\u30FA\u30FC-\u30FF\u3105-\u312F\u3131-\u318E\u31A0-\u31BF\u31F0-\u31FF\u3400-\u4DBF\u4E00-\u9FFC\uA000-\uA48C\uA4D0-\uA4FD\uA500-\uA60C\uA610-\uA62B\uA640-\uA66F\uA674-\uA67D\uA67F-\uA6F1\uA717-\uA71F\uA722-\uA788\uA78B-\uA7BF\uA7C2-\uA7CA\uA7F5-\uA827\uA82C\uA840-\uA873\uA880-\uA8C5\uA8D0-\uA8D9\uA8E0-\uA8F7\uA8FB\uA8FD-\uA92D\uA930-\uA953\uA960-\uA97C\uA980-\uA9C0\uA9CF-\uA9D9\uA9E0-\uA9FE\uAA00-\uAA36\uAA40-\uAA4D\uAA50-\uAA59\uAA60-\uAA76\uAA7A-\uAAC2\uAADB-\uAADD\uAAE0-\uAAEF\uAAF2-\uAAF6\uAB01-\uAB06\uAB09-\uAB0E\uAB11-\uAB16\uAB20-\uAB26\uAB28-\uAB2E\uAB30-\uAB5A\uAB5C-\uAB69\uAB70-\uABEA\uABEC\uABED\uABF0-\uABF9\uAC00-\uD7A3\uD7B0-\uD7C6\uD7CB-\uD7FB\uF900-\uFA6D\uFA70-\uFAD9\uFB00-\uFB06\uFB13-\uFB17\uFB1D-\uFB28\uFB2A-\uFB36\uFB38-\uFB3C\uFB3E\uFB40\uFB41\uFB43\uFB44\uFB46-\uFBB1\uFBD3-\uFD3D\uFD50-\uFD8F\uFD92-\uFDC7\uFDF0-\uFDFB\uFE00-\uFE0F\uFE20-\uFE2F\uFE33\uFE34\uFE4D-\uFE4F\uFE70-\uFE74\uFE76-\uFEFC\uFF10-\uFF19\uFF21-\uFF3A\uFF3F\uFF41-\uFF5A\uFF66-\uFFBE\uFFC2-\uFFC7\uFFCA-\uFFCF\uFFD2-\uFFD7\uFFDA-\uFFDC]|\uD800[\uDC00-\uDC0B\uDC0D-\uDC26\uDC28-\uDC3A\uDC3C\uDC3D\uDC3F-\uDC4D\uDC50-\uDC5D\uDC80-\uDCFA\uDD40-\uDD74\uDDFD\uDE80-\uDE9C\uDEA0-\uDED0\uDEE0\uDF00-\uDF1F\uDF2D-\uDF4A\uDF50-\uDF7A\uDF80-\uDF9D\uDFA0-\uDFC3\uDFC8-\uDFCF\uDFD1-\uDFD5]|\uD801[\uDC00-\uDC9D\uDCA0-\uDCA9\uDCB0-\uDCD3\uDCD8-\uDCFB\uDD00-\uDD27\uDD30-\uDD63\uDE00-\uDF36\uDF40-\uDF55\uDF60-\uDF67]|\uD802[\uDC00-\uDC05\uDC08\uDC0A-\uDC35\uDC37\uDC38\uDC3C\uDC3F-\uDC55\uDC60-\uDC76\uDC80-\uDC9E\uDCE0-\uDCF2\uDCF4\uDCF5\uDD00-\uDD15\uDD20-\uDD39\uDD80-\uDDB7\uDDBE\uDDBF\uDE00-\uDE03\uDE05\uDE06\uDE0C-\uDE13\uDE15-\uDE17\uDE19-\uDE35\uDE38-\uDE3A\uDE3F\uDE60-\uDE7C\uDE80-\uDE9C\uDEC0-\uDEC7\uDEC9-\uDEE6\uDF00-\uDF35\uDF40-\uDF55\uDF60-\uDF72\uDF80-\uDF91]|\uD803[\uDC00-\uDC48\uDC80-\uDCB2\uDCC0-\uDCF2\uDD00-\uDD27\uDD30-\uDD39\uDE80-\uDEA9\uDEAB\uDEAC\uDEB0\uDEB1\uDF00-\uDF1C\uDF27\uDF30-\uDF50\uDFB0-\uDFC4\uDFE0-\uDFF6]|\uD804[\uDC00-\uDC46\uDC66-\uDC6F\uDC7F-\uDCBA\uDCD0-\uDCE8\uDCF0-\uDCF9\uDD00-\uDD34\uDD36-\uDD3F\uDD44-\uDD47\uDD50-\uDD73\uDD76\uDD80-\uDDC4\uDDC9-\uDDCC\uDDCE-\uDDDA\uDDDC\uDE00-\uDE11\uDE13-\uDE37\uDE3E\uDE80-\uDE86\uDE88\uDE8A-\uDE8D\uDE8F-\uDE9D\uDE9F-\uDEA8\uDEB0-\uDEEA\uDEF0-\uDEF9\uDF00-\uDF03\uDF05-\uDF0C\uDF0F\uDF10\uDF13-\uDF28\uDF2A-\uDF30\uDF32\uDF33\uDF35-\uDF39\uDF3B-\uDF44\uDF47\uDF48\uDF4B-\uDF4D\uDF50\uDF57\uDF5D-\uDF63\uDF66-\uDF6C\uDF70-\uDF74]|\uD805[\uDC00-\uDC4A\uDC50-\uDC59\uDC5E-\uDC61\uDC80-\uDCC5\uDCC7\uDCD0-\uDCD9\uDD80-\uDDB5\uDDB8-\uDDC0\uDDD8-\uDDDD\uDE00-\uDE40\uDE44\uDE50-\uDE59\uDE80-\uDEB8\uDEC0-\uDEC9\uDF00-\uDF1A\uDF1D-\uDF2B\uDF30-\uDF39]|\uD806[\uDC00-\uDC3A\uDCA0-\uDCE9\uDCFF-\uDD06\uDD09\uDD0C-\uDD13\uDD15\uDD16\uDD18-\uDD35\uDD37\uDD38\uDD3B-\uDD43\uDD50-\uDD59\uDDA0-\uDDA7\uDDAA-\uDDD7\uDDDA-\uDDE1\uDDE3\uDDE4\uDE00-\uDE3E\uDE47\uDE50-\uDE99\uDE9D\uDEC0-\uDEF8]|\uD807[\uDC00-\uDC08\uDC0A-\uDC36\uDC38-\uDC40\uDC50-\uDC59\uDC72-\uDC8F\uDC92-\uDCA7\uDCA9-\uDCB6\uDD00-\uDD06\uDD08\uDD09\uDD0B-\uDD36\uDD3A\uDD3C\uDD3D\uDD3F-\uDD47\uDD50-\uDD59\uDD60-\uDD65\uDD67\uDD68\uDD6A-\uDD8E\uDD90\uDD91\uDD93-\uDD98\uDDA0-\uDDA9\uDEE0-\uDEF6\uDFB0]|\uD808[\uDC00-\uDF99]|\uD809[\uDC00-\uDC6E\uDC80-\uDD43]|[\uD80C\uD81C-\uD820\uD822\uD840-\uD868\uD86A-\uD86C\uD86F-\uD872\uD874-\uD879\uD880-\uD883][\uDC00-\uDFFF]|\uD80D[\uDC00-\uDC2E]|\uD811[\uDC00-\uDE46]|\uD81A[\uDC00-\uDE38\uDE40-\uDE5E\uDE60-\uDE69\uDED0-\uDEED\uDEF0-\uDEF4\uDF00-\uDF36\uDF40-\uDF43\uDF50-\uDF59\uDF63-\uDF77\uDF7D-\uDF8F]|\uD81B[\uDE40-\uDE7F\uDF00-\uDF4A\uDF4F-\uDF87\uDF8F-\uDF9F\uDFE0\uDFE1\uDFE3\uDFE4\uDFF0\uDFF1]|\uD821[\uDC00-\uDFF7]|\uD823[\uDC00-\uDCD5\uDD00-\uDD08]|\uD82C[\uDC00-\uDD1E\uDD50-\uDD52\uDD64-\uDD67\uDD70-\uDEFB]|\uD82F[\uDC00-\uDC6A\uDC70-\uDC7C\uDC80-\uDC88\uDC90-\uDC99\uDC9D\uDC9E]|\uD834[\uDD65-\uDD69\uDD6D-\uDD72\uDD7B-\uDD82\uDD85-\uDD8B\uDDAA-\uDDAD\uDE42-\uDE44]|\uD835[\uDC00-\uDC54\uDC56-\uDC9C\uDC9E\uDC9F\uDCA2\uDCA5\uDCA6\uDCA9-\uDCAC\uDCAE-\uDCB9\uDCBB\uDCBD-\uDCC3\uDCC5-\uDD05\uDD07-\uDD0A\uDD0D-\uDD14\uDD16-\uDD1C\uDD1E-\uDD39\uDD3B-\uDD3E\uDD40-\uDD44\uDD46\uDD4A-\uDD50\uDD52-\uDEA5\uDEA8-\uDEC0\uDEC2-\uDEDA\uDEDC-\uDEFA\uDEFC-\uDF14\uDF16-\uDF34\uDF36-\uDF4E\uDF50-\uDF6E\uDF70-\uDF88\uDF8A-\uDFA8\uDFAA-\uDFC2\uDFC4-\uDFCB\uDFCE-\uDFFF]|\uD836[\uDE00-\uDE36\uDE3B-\uDE6C\uDE75\uDE84\uDE9B-\uDE9F\uDEA1-\uDEAF]|\uD838[\uDC00-\uDC06\uDC08-\uDC18\uDC1B-\uDC21\uDC23\uDC24\uDC26-\uDC2A\uDD00-\uDD2C\uDD30-\uDD3D\uDD40-\uDD49\uDD4E\uDEC0-\uDEF9]|\uD83A[\uDC00-\uDCC4\uDCD0-\uDCD6\uDD00-\uDD4B\uDD50-\uDD59]|\uD83B[\uDE00-\uDE03\uDE05-\uDE1F\uDE21\uDE22\uDE24\uDE27\uDE29-\uDE32\uDE34-\uDE37\uDE39\uDE3B\uDE42\uDE47\uDE49\uDE4B\uDE4D-\uDE4F\uDE51\uDE52\uDE54\uDE57\uDE59\uDE5B\uDE5D\uDE5F\uDE61\uDE62\uDE64\uDE67-\uDE6A\uDE6C-\uDE72\uDE74-\uDE77\uDE79-\uDE7C\uDE7E\uDE80-\uDE89\uDE8B-\uDE9B\uDEA1-\uDEA3\uDEA5-\uDEA9\uDEAB-\uDEBB]|\uD83E[\uDFF0-\uDFF9]|\uD869[\uDC00-\uDEDD\uDF00-\uDFFF]|\uD86D[\uDC00-\uDF34\uDF40-\uDFFF]|\uD86E[\uDC00-\uDC1D\uDC20-\uDFFF]|\uD873[\uDC00-\uDEA1\uDEB0-\uDFFF]|\uD87A[\uDC00-\uDFE0]|\uD87E[\uDC00-\uDE1D]|\uD884[\uDC00-\uDF4A]|\uDB40[\uDD00-\uDDEF])",
    ];

    for regex in REGEXES {
        let regex = tc.compile(regex);
        for code_point in CODE_POINTS {
            regex.test_succeeds(code_point);
        }
    }
}

#[test]
fn test_valid_character_sets_in_annex_b() {
    test_with_configs(test_valid_character_sets_in_annex_b_tc)
}

fn test_valid_character_sets_in_annex_b_tc(tc: TestConfig) {
    // From: https://github.com/boa-dev/boa/issues/2794
    let regexp = r"[a-\s]";
    tc.test_match_succeeds(regexp, "", "a");
    tc.test_match_succeeds(regexp, "", "-");
    tc.test_match_succeeds(regexp, "", " ");
    tc.test_match_fails(regexp, "", "s");
    tc.test_match_fails(regexp, "", "$");

    let regexp = r"[\d-z]";
    tc.test_match_succeeds(regexp, "", "z");
    tc.test_match_succeeds(regexp, "", "1");
    tc.test_match_succeeds(regexp, "", "7");
    tc.test_match_succeeds(regexp, "", "9");
    tc.test_match_fails(regexp, "", "a");
    tc.test_match_fails(regexp, "", "f");
    tc.test_match_fails(regexp, "", " ");
}

#[test]
fn test_escapes_folding() {
    test_with_configs(test_escapes_folding_tc)
}

fn test_escapes_folding_tc(tc: TestConfig) {
    // Regression test for failing to fold characters which come from escapes.
    tc.test_match_fails(r"\u{41}", "", "a");
    tc.test_match_succeeds(r"\u{41}", "", "A");
    tc.test_match_fails(r"\u{61}", "", "A");
    tc.test_match_succeeds(r"\u{61}", "", "a");
    tc.test_match_succeeds(r"\u{41}", "i", "a");
    tc.test_match_succeeds(r"\u{41}", "i", "A");
    tc.test_match_succeeds(r"\u{61}", "i", "a");
    tc.test_match_succeeds(r"\u{61}", "i", "A");
}

#[test]
fn test_high_folds() {
    test_with_configs(test_high_folds_tc)
}

fn test_high_folds_tc(tc: TestConfig) {
    // Regression test for bogus folding.
    // We incorrectly folded certain characters in delta blocks:
    // we folded U+100 to U+101 (correctly) but then U+101 to U+102 (wrong).
    tc.test_match_succeeds(r"\u{100}", "", "\u{100}");
    tc.test_match_succeeds(r"\u{100}", "i", "\u{100}");

    tc.test_match_fails(r"\u{100}", "", "\u{101}");
    tc.test_match_succeeds(r"\u{100}", "i", "\u{101}");

    tc.test_match_succeeds(r"\u{101}", "", "\u{101}");
    tc.test_match_succeeds(r"\u{101}", "i", "\u{101}");

    tc.test_match_fails(r"\u{101}", "", "\u{102}");
    tc.test_match_fails(r"\u{101}", "i", "\u{102}");

    // Exercise a "mod 4 range":
    //   U+1B8 folds to U+1B9
    //   U+1BC folds to U+1BD
    // Codepoints between fold to themselves.
    tc.test_match_succeeds(r"\u{1B8}", "", "\u{1B8}");
    tc.test_match_succeeds(r"\u{1B8}", "i", "\u{1B8}");
    tc.test_match_fails(r"\u{1B8}", "", "\u{1B9}");
    tc.test_match_succeeds(r"\u{1B8}", "i", "\u{1B9}");
    tc.test_match_succeeds(r"\u{1B9}", "", "\u{1B9}");
    tc.test_match_succeeds(r"\u{1B9}", "i", "\u{1B9}");
    tc.test_match_fails(r"\u{1B9}", "", "\u{1BA}");
    tc.test_match_fails(r"\u{1B9}", "i", "\u{1BA}");
    tc.test_match_succeeds(r"\u{1BC}", "", "\u{1BC}");
    tc.test_match_succeeds(r"\u{1BC}", "i", "\u{1BC}");
    tc.test_match_fails(r"\u{1BC}", "", "\u{1BD}");
    tc.test_match_succeeds(r"\u{1BC}", "i", "\u{1BD}");
    tc.test_match_succeeds(r"\u{1BD}", "", "\u{1BD}");
    tc.test_match_succeeds(r"\u{1BD}", "i", "\u{1BD}");
    tc.test_match_fails(r"\u{1BD}", "", "\u{1BE}");
    tc.test_match_fails(r"\u{1BD}", "i", "\u{1BE}");
}

#[test]
fn test_invalid_quantifier_loop() {
    test_with_configs(test_invalid_quantifier_loop_tc)
}

fn test_invalid_quantifier_loop_tc(tc: TestConfig) {
    tc.test_match_fails(r#"\c*"#, "", "\n");
}

#[test]
fn test_empty_brackets() {
    // Regression test for issue 99.
    test_with_configs(|tc: TestConfig| {
        tc.test_match_succeeds(r#"[x]*a"#, "", "a");
        tc.test_match_succeeds(r#"[]*a"#, "", "a");
        tc.test_match_succeeds(r#"[^\s\S]*a"#, "", "a");
        tc.test_match_fails(r#"[x]*a"#, "", "b");
        tc.test_match_fails(r#"[]*a"#, "", "b");
        tc.test_match_fails(r#"[^\s\S]a"#, "", "a");
    })
}

#[test]
fn test_keeps_capture_groups_for_impossible_matches() {
    // Regression test for the following issue:
    // branches which can never match a string but contain a capture group
    // were being incorrectly removed, leading to capture group misnumbering.
    test_with_configs(|tc: TestConfig| {
        tc.test_match_succeeds(r#"(?:[](fail))?(capture)"#, "", "capture");
    })
}

#[test]
fn test_just_fails() {
    test_with_configs(|tc: TestConfig| {
        // Test cases where some part of the regex is guaranteed to fail.
        tc.test_match_fails(r#"abc[]def"#, "", "abcdef");
        tc.test_match_fails(r#"abc[^\s\S]def"#, "", "abcdef");
        tc.test_match_succeeds(r#"(:?fail[])|x"#, "", "x");
        tc.test_match_succeeds(r#"(fail[])|x"#, "", "x");
        tc.test_match_succeeds(r#"(fail[^\s\S])|x"#, "", "x");
    })
}

#[test]
fn test_unicode_folding() {
    test_with_configs_no_ascii(test_unicode_folding_tc)
}

/// 262 test/language/literals/regexp/u-case-mapping.js
fn test_unicode_folding_tc(tc: TestConfig) {
    tc.test_match_fails(r"\u{212A}", "i", "k");
    tc.test_match_fails(r"\u{212A}", "i", "K");
    tc.test_match_fails(r"\u{212A}", "u", "k");
    tc.test_match_fails(r"\u{212A}", "u", "K");
    tc.test_match_succeeds(r"\u{212A}", "iu", "k");
    tc.test_match_succeeds(r"\u{212A}", "iu", "K");
}

#[test]
fn test_class_invalid_control_character() {
    test_with_configs(test_class_invalid_control_character_tc)
}

fn test_class_invalid_control_character_tc(tc: TestConfig) {
    tc.test_match_succeeds("[\\c\u{0}]", "", "\\");
    tc.test_match_succeeds("[\\c\u{0}]", "", "c");
    tc.test_match_succeeds("[\\c\u{0}]", "", "\u{0}");
}

#[test]
fn test_quantifiable_assertion_not_followed_by() {
    test_with_configs(test_quantifiable_assertion_not_followed_by_tc)
}

/// 262 test/annexB/language/literals/regexp/quantifiable-assertion-not-followed-by.js
fn test_quantifiable_assertion_not_followed_by_tc(tc: TestConfig) {
    tc.compile(r#"[a-e](?!Z)*"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("a");
    tc.compile(r#"[a-e](?!Z)+"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("e");
    tc.compile(r#"[a-e](?!Z)?"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("a");
    tc.compile(r#"[a-e](?!Z){2}"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("e");
    tc.compile(r#"[a-e](?!Z){2,}"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("e");
    tc.compile(r#"[a-e](?!Z){2,3}"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("e");
    tc.compile(r#"[a-e](?!Z)*?"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("a");
    tc.compile(r#"[a-e](?!Z)+?"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("e");
    tc.compile(r#"[a-e](?!Z)??"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("a");
    tc.compile(r#"[a-e](?!Z){2}?"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("e");
    tc.compile(r#"[a-e](?!Z){2,}?"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("e");
    tc.compile(r#"[a-e](?!Z){2,3}?"#)
        .match1f(r#"aZZZZ bZZZ cZZ dZ e"#)
        .test_eq("e");
}

#[test]
fn test_quantifiable_assertion_followed_by() {
    test_with_configs(test_quantifiable_assertion_followed_by_tc)
}

/// 262 test/annexB/language/literals/regexp/quantifiable-assertion-followed-by.js
fn test_quantifiable_assertion_followed_by_tc(tc: TestConfig) {
    tc.compile(r#".(?=Z)*"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("a");
    tc.compile(r#".(?=Z)+"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("b");
    tc.compile(r#".(?=Z)?"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("a");
    tc.compile(r#".(?=Z){2}"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("b");
    tc.compile(r#".(?=Z){2,}"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("b");
    tc.compile(r#".(?=Z){2,3}"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("b");
    tc.compile(r#".(?=Z)*?"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("a");
    tc.compile(r#".(?=Z)+?"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("b");
    tc.compile(r#".(?=Z)??"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("a");
    tc.compile(r#".(?=Z){2}?"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("b");
    tc.compile(r#".(?=Z){2,}?"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("b");
    tc.compile(r#".(?=Z){2,3}?"#)
        .match1f(r#"a bZ cZZ dZZZ eZZZZ"#)
        .test_eq("b");
}

#[cfg(feature = "utf16")]
mod utf16_tests {
    use super::*;

    #[test]
    fn test_utf16_regression_100() {
        test_with_configs(test_utf16_regression_100_tc)
    }

    fn test_utf16_regression_100_tc(tc: TestConfig) {
        // Ensure the leading bytes of UTF-16 characters don't match against brackets.
        let input = "赔"; // U+8D54

        let re = tc.compile(r"[A-Z]"); // 0x41 - 0x5A
        let matched = re.find_utf16(input);
        assert!(matched.is_none());

        let matched = re.find_ucs2(input);
        assert!(matched.is_none());
    }

    #[test]
    fn test_utf16_byte_sequences() {
        test_with_configs(test_utf16_byte_sequences_tc)
    }

    fn test_utf16_byte_sequences_tc(tc: TestConfig) {
        // Regress emits byte sequences for e.g. 'abc'.
        // Ensure these are properly decoded in UTF-16/UCS2.
        for flags in ["", "i", "u", "iu"] {
            let re = tc.compilef(r"abc", flags);

            let input = "abc";
            let matched = re.find_utf16(input);
            assert!(matched.is_some());
            assert_eq!(matched.unwrap().range, 0..3);

            let matched = re.find_ucs2(input);
            assert!(matched.is_some());
            assert_eq!(matched.unwrap().range, 0..3);

            let input = "xxxabczzz";
            let matched = re.find_utf16(input);
            assert!(matched.is_some());
            assert_eq!(matched.unwrap().range, 3..6);

            let matched = re.find_ucs2(input);
            assert!(matched.is_some());
            assert_eq!(matched.unwrap().range, 3..6);
        }
    }

    #[test]
    fn test_utf16_regression_101() {
        test_with_configs(test_utf16_regression_101_tc)
    }

    fn test_utf16_regression_101_tc(tc: TestConfig) {
        for flags in ["", "i", "u", "iu"] {
            let re = tc.compilef(r"foo", flags);
            let matched = re.find_ucs2("football");
            assert!(matched.is_some());
            assert_eq!(matched.unwrap().range, 0..3);
        }
    }

    #[test]
    fn test_ucs2_surrogates() {
        // Test that we can match against surrogates in UCS-2 mode.
        // TODO: we improperly match this in UTF-16 mode, because our API is
        // kind of bad. We ought to infer UTF-16 vs UCS2 from the "u" flag,
        // matching the JS spec.
        let re = regress::Regex::new(r"[\uD800-\uDBFF]").unwrap();

        // High surrogate.
        let matched = re.find_from_ucs2(&[0xD800], 0).next();
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().range, 0..1);

        let input = to_utf16("😀");
        let matched = re.find_from_ucs2(&input, 0).next();
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().range, 0..1);

        // Low surrogate.
        let re = regress::Regex::new(r"[\uDC00-\uDFFF]").unwrap();
        let matched = re.find_from_ucs2(&[1, 2, 3, 0xDC00], 0).next();
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().range, 3..4);

        let input = to_utf16("😀");
        let matched = re.find_from_ucs2(&input, 0).next();
        assert!(matched.is_some());
        assert_eq!(matched.unwrap().range, 1..2);
    }
}

#[test]
fn test_range_from_utf16() {
    use std::char::decode_utf16;
    let weird_utf8 = "a🌍b\u{1F600}q"; // 'a', '🌍', 'b', '😀', 'q'
    let utf16: Vec<u16> = to_utf16(weird_utf8);
    assert_eq!(utf16, weird_utf8.encode_utf16().collect::<Vec<_>>());

    // Define all possible ranges in UTF-16
    for start in 0..utf16.len() {
        for end in start..=utf16.len() {
            let utf16_range = start..end;

            // The prefix and body must not split surrogate pairs, else we cannot convert the range.
            if decode_utf16(utf16[0..utf16_range.end].iter().copied()).any(|r| r.is_err()) {
                continue;
            }
            if decode_utf16(utf16[utf16_range.clone()].iter().copied()).any(|r| r.is_err()) {
                continue;
            }

            let utf16_to_utf8: String = decode_utf16(utf16[utf16_range.clone()].iter().copied())
                .map(|r| r.unwrap())
                .collect();

            let utf8_range = range_from_utf16(&utf16, utf16_range);
            assert_eq!(&weird_utf8[utf8_range], utf16_to_utf8);
        }
    }
}

#[test]
fn test_anchored_optimization() {
    test_with_configs(test_anchored_optimization_tc)
}

fn test_anchored_optimization_tc(tc: TestConfig) {
    // Test basic anchored matching with ^
    tc.compile(r"^hello")
        .match1f("hello world")
        .test_eq("hello");
    tc.compile(r"^hello").test_fails("  hello world"); // Should not match when not at start

    // Test anchored regex with whitespace
    tc.compile(r"^hello\s+world")
        .match1f("hello   world")
        .test_eq("hello   world");
    tc.compile(r"^hello\s+world").test_fails("  hello world"); // Should not match when not at start

    // Test anchored regex with capture groups
    tc.compile(r"^(\w+)=(\d+)")
        .match1f("key=123 other=456")
        .test_eq("key=123,key,123");
    tc.compile(r"^(\w+)=(\d+)").test_fails(" key=123"); // Should not match when not at start

    // Test anchored alternation
    tc.compile(r"^(abc|def)").match1f("abc").test_eq("abc,abc");
    tc.compile(r"^(abc|def)").match1f("def").test_eq("def,def");
    tc.compile(r"^(abc|def)").test_fails(" abc");

    // Test anchored regex with multiline flag
    tc.compilef(r"^hello", "m")
        .match1f("world\nhello")
        .test_eq("hello");

    // Test that non-anchored regexes still work normally
    tc.compile(r"abc").match1f("xabc").test_eq("abc");
    tc.compile(r"abc").match1f("abcx").test_eq("abc");
}

#[test]
fn test_non_greedy_quantifiers() {
    test_with_configs(test_non_greedy_quantifiers_tc)
}

fn test_non_greedy_quantifiers_tc(tc: TestConfig) {
    // Test that non-greedy quantifiers match minimally
    tc.compile(r"a.*?b")
        .match1f("aXXXXbYYYYb")
        .test_eq("aXXXXb");
    tc.compile(r"a.+?b")
        .match1f("aXXXXbYYYYb")
        .test_eq("aXXXXb");

    // Test difference between greedy and non-greedy
    tc.compile(r"a.*b")
        .match1f("aXXXXbYYYYb")
        .test_eq("aXXXXbYYYYb");
    tc.compile(r"a.*?b")
        .match1f("aXXXXbYYYYb")
        .test_eq("aXXXXb");

    // Test non-greedy with capture groups
    tc.compile(r"a(.*?)b")
        .match1f("aXXXXbYYYYb")
        .test_eq("aXXXXb,XXXX");
    tc.compile(r"a(.*)b")
        .match1f("aXXXXbYYYYb")
        .test_eq("aXXXXbYYYYb,XXXXbYYYY");

    // Test non-greedy quantifier at end of string
    tc.compile(r"a.*?$").match1f("aXXXX").test_eq("aXXXX");

    // Test multiple non-greedy quantifiers
    tc.compile(r"a.*?b.*?c").match1f("aXbYcZ").test_eq("aXbYc");

    // Test non-greedy with alternation
    tc.compile(r"(a|b)*?c").match1f("ababc").test_eq("ababc,b");

    // Test zero-width non-greedy match
    tc.compile(r"a.*?a").match1f("aa").test_eq("aa");
}

#[test]
fn test_empty_alternation_in_capture() {
    test_with_configs(test_empty_alternation_in_capture_tc)
}

fn test_empty_alternation_in_capture_tc(tc: TestConfig) {
    // Regression tests for empty alternations in capture groups.
    tc.compile("(z|)*?x").match1f("z0x").test_eq("x,");
}

// TC39 proposal: duplicate named capturing groups in different alternatives
fn test_duplicate_named_groups_tc(tc: TestConfig) {
    // Basic duplicate named groups in alternatives - the example from the TC39 proposal
    let m = tc
        .compile(r"(?<year>[0-9]{4})-[0-9]{2}|[0-9]{2}-(?<year>[0-9]{4})")
        .find("2025-12")
        .unwrap();
    assert_eq!(m.group(0), Some(0..7));
    assert_eq!(m.group(1), Some(0..4));
    let ng = m.named_groups();
    assert!(ng.eq([("year", Some(0..4))]));

    // Test the other alternative
    let m = tc
        .compile(r"(?<year>[0-9]{4})-[0-9]{2}|[0-9]{2}-(?<year>[0-9]{4})")
        .find("12-2025")
        .unwrap();
    assert_eq!(m.group(0), Some(0..7));
    assert_eq!(m.group(2), Some(3..7));
    let ng = m.named_groups();
    assert!(ng.eq([("year", Some(3..7))]));

    // Duplicate names in nested alternatives
    let m = tc.compile(r"(?:(?<a>x)|(?<a>y))").find("x").unwrap();
    let ng = m.named_groups();
    assert!(ng.eq([("a", Some(0..1))]));

    let m = tc.compile(r"(?:(?<a>x)|(?<a>y))").find("y").unwrap();
    let ng = m.named_groups();
    assert!(ng.eq([("a", Some(0..1))]));

    // Multiple duplicate names
    let m = tc
        .compile(r"(?<x>a)(?<y>b)|(?<x>c)(?<y>d)")
        .find("ab")
        .unwrap();
    let ng = m.named_groups();
    assert!(ng.eq([("x", Some(0..1)), ("y", Some(1..2))]));

    let m = tc
        .compile(r"(?<x>a)(?<y>b)|(?<x>c)(?<y>d)")
        .find("cd")
        .unwrap();
    let ng = m.named_groups();
    assert!(ng.eq([("x", Some(0..1)), ("y", Some(1..2))]));

    // Backreferences with duplicate names
    // TODO: Backreferences with duplicate named groups require additional work
    // in the matcher to determine which group participated. This is deferred.
    //let m = tc.compile(r"(?:(?<a>x)|(?<a>y))\k<a>")
    //    .find("xx")
    //    .unwrap();
    //assert_eq!(m.group(0), Some(0..2));

    //let m = tc.compile(r"(?:(?<a>x)|(?<a>y))\k<a>")
    //    .find("yy")
    //    .unwrap();
    //assert_eq!(m.group(0), Some(0..2));

    //// Should NOT match when backreference doesn't match
    //assert!(tc.compile(r"(?:(?<a>x)|(?<a>y))\k<a>")
    //    .find("xy")
    //    .is_none());
}

#[test]
fn test_duplicate_named_groups() {
    test_with_configs(test_duplicate_named_groups_tc)
}

// Test that duplicates in the SAME alternative are still rejected
#[test]
fn test_duplicate_named_groups_same_alternative_rejected() {
    use regress::Regex;

    // Should reject duplicates in the same alternative
    assert!(Regex::new(r"(?<name>a)(?<name>b)").is_err());
    assert!(Regex::new(r"(?<x>a)b(?<x>c)").is_err());

    // Should reject duplicates in nested groups within same alternative
    assert!(Regex::new(r"(?<a>x)(?:(?<a>y))").is_err());
}

#[test]
fn test_ascii_unicode_icase_backref() {
    test_with_configs(|tc| {
        // Regression test for ASCII with Unicode case-insensitive folding.
        let re = tc.compilef(r"^(x)\1$", "iu");
        re.test_succeeds("xx");
        re.test_succeeds("XX");
        re.test_fails("xy");
        re.test_fails("XY");
    })
}

#[test]
fn test_duplicate_named_groups_distinct_alternations_backref() {
    test_with_configs(test_duplicate_named_groups_distinct_alternations_backref_tc)
}

// A named backreference to an alternation with duplicate named groups
// should only match the group which participated in the match.
fn test_duplicate_named_groups_distinct_alternations_backref_tc(tc: TestConfig) {
    let pattern = r"^(?:(?<a>x)|(?<a>y))\k<a>$";

    // Alterations with duplicate names groups: backref should match whichever group matched.
    let re = tc.compile(pattern);
    re.test_succeeds("xx");
    re.test_succeeds("yy");
    re.test_fails("xy");
    re.test_fails("yx");

    // Same but icase
    let re = tc.compilef(pattern, "i");
    re.test_succeeds("XX");
    re.test_succeeds("YY");
    re.test_fails("XY");
    re.test_fails("YX");

    // Same but unicode
    let re = tc.compilef(pattern, "u");
    re.test_succeeds("xx");
    re.test_succeeds("yy");
    re.test_fails("xy");
    re.test_fails("yx");

    // Same but icase unicode
    let re = tc.compilef(pattern, "iu");
    re.test_succeeds("XX");
    re.test_succeeds("YY");
    re.test_fails("XY");
    re.test_fails("YX");
}

#[test]
fn test_regression_142() {
    // Regression test for issue #142.
    use regress::Regex;
    let _ = Regex::with_flags(r"\p{scx=Cyrl}", "u").expect("Should succeed");
}

#[test]
fn test_lookbehind_long_byteseq_regression_146() {
    // Regression test for issue #146.
    // Lookbehinds reverse the order of their instructions but not the literal byte sequences
    // for fast memcmp. If the byte sequence is overlong, the emitter splits it; ensure that the
    // splits are properly reversed.
    test_with_configs(|tc| {
        // In lookbehind, instruction order is reversed, but ByteSequence
        // contents are not. So splitting a long literal into chunks must still
        // preserve correct backward execution at every length.
        // Original report:
        const REPORTED_NEEDLE: &str = r"(?<=aaaa={bbbbbbbbbb:c)";
        const REPORTED_HAYSTACK: &str = r#"aaaa={bbbbbbbbbb:c"#;
        assert_eq!(
            tc.compile(REPORTED_NEEDLE)
                .find(REPORTED_HAYSTACK)
                .map(|m| m.range()),
            Some(REPORTED_HAYSTACK.len()..REPORTED_HAYSTACK.len())
        );

        // Exhaustive test.
        const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-=";
        let mut it = ALPHABET.chars().cycle();
        for len in 0..=128 {
            let haystack: String = it.by_ref().take(len).collect();
            let needle = format!(r"(?<={haystack})");
            assert_eq!(
                tc.compile(&needle).find(&haystack).map(|m| m.range()),
                Some(len..len),
                "len={len}"
            );
        }
    })
}

#[test]
fn test_high_unicode_folds_to_ascii() {
    test_with_configs(test_high_unicode_folds_to_ascii_tc)
}

fn test_high_unicode_folds_to_ascii_tc(tc: TestConfig) {
    // The Kelvin character (U+212A) case-folds to lowercase k,
    // which means that it's a word character iff we're using case-insensitive Unicode.
    tc.test_match_fails(r"\b\u212A", "", "\u{212A}");
    tc.test_match_succeeds(r"\b\u212A", "iu", "\u{212A}");
    tc.test_match_fails(r"^\w$", "", "\u{212A}");
    tc.test_match_succeeds(r"^\w$", "iu", "\u{212A}");
    // \W should NOT match Kelvin in icase unicode mode (since it's a word char)
    tc.test_match_succeeds(r"^\W$", "", "\u{212A}");
    tc.test_match_fails(r"^\W$", "iu", "\u{212A}");

    // U+017F (Latin Small Letter Long S) case-folds to 's'.
    tc.test_match_fails(r"\b\u017F", "", "\u{017F}");
    tc.test_match_succeeds(r"\b\u017F", "iu", "\u{017F}");
    tc.test_match_fails(r"^\w$", "", "\u{017F}");
    tc.test_match_succeeds(r"^\w$", "iu", "\u{017F}");
    tc.test_match_succeeds(r"^\W$", "", "\u{017F}");
    tc.test_match_fails(r"^\W$", "iu", "\u{017F}");

    // U+0131 (Latin Small Letter Dotless I) does NOT case-fold to ASCII.
    tc.test_match_fails(r"\b\u0131", "", "\u{0131}");
    tc.test_match_fails(r"\b\u0131", "iu", "\u{0131}");
    tc.test_match_fails(r"^\w$", "", "\u{0131}");
    tc.test_match_fails(r"^\w$", "iu", "\u{0131}");
    tc.test_match_succeeds(r"^\W$", "", "\u{0131}");
    tc.test_match_succeeds(r"^\W$", "iu", "\u{0131}");
}

// Regression test for the case where a non-capturing group precedes the named groups,
// which could cause off-by-one errors in group index tracking.
#[test]
fn test_duplicate_named_groups_with_noncapturing_prefix() {
    test_with_configs(|tc| {
        let pattern = r"^(?:(?<a>x)|(?<a>y))\k<a>$";

        // Backrefs should match whichever group matched.
        let re = tc.compile(pattern);
        re.test_succeeds("xx");
        re.test_succeeds("yy");
        re.test_fails("xy");
        re.test_fails("yx");
    })
}
