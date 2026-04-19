use std::env;
use std::fmt;
use std::fs::{self, File};
use std::io::Write;
use std::num::Wrapping;
use std::path::Path;

const POLY: u8 = 0x1D;
const PROTO_FILES: &[&str] = &[
    "protobuf/version.proto",
    "protobuf/wrapped/share.proto",
    "protobuf/wrapped/secret.proto",
    "protobuf/dss/share.proto",
    "protobuf/dss/metadata.proto",
    "protobuf/dss/secret.proto",
];

/// Replicates the least significant bit to every other bit.
#[inline]
fn mask(bit: u8) -> u8 {
    (Wrapping(0u8) - Wrapping(bit & 1)).0
}

/// Multiplies a polynomial with x and returns the residual
/// of the polynomial division with POLY as divisor.
#[inline]
fn xtimes(poly: u8) -> u8 {
    (poly << 1) ^ (mask(poly >> 7) & POLY)
}

struct Tables {
    exp: [u8; 256],
    log: [u8; 256],
}

fn generate_tables(file: &mut File) {
    let mut tabs = Tables {
        exp: [0; 256],
        log: [0; 256],
    };

    let mut tmp = 1;
    for power in 0..255usize {
        tabs.exp[power] = tmp;
        tabs.log[tmp as usize] = power as u8;
        tmp = xtimes(tmp);
    }
    tabs.exp[255] = 1;

    write!(file, "{}", tabs).expect("Could not format the table. Aborting build.");
}

fn farray(array: [u8; 256], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for (index, value) in array.into_iter().enumerate() {
        write!(f, "{}", value)?;
        if index != array.len() - 1 {
            write!(f, ",")?;
        }
    }
    Ok(())
}

impl fmt::Display for Tables {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Tables {{")?;
        write!(f, "    exp: [")?;
        farray(self.exp, f)?;
        writeln!(f, "],")?;
        write!(f, "    log: [")?;
        farray(self.log, f)?;
        writeln!(f, "]")?;
        write!(f, "}};")
    }
}

fn path_str(path: &Path) -> &str {
    path.to_str()
        .expect("Generated protobuf output path must be valid UTF-8")
}

fn rust_path_literal(path: &Path) -> String {
    format!("{:?}", path_str(path))
}

fn generate_gf256_tables(out_dir: &Path) {
    let dest = out_dir.join("nothinghardcoded.rs");
    let mut file = File::create(&dest).expect("Could not create GF(256) lookup table output");

    write!(
        file,
        "pub struct Tables {{ \
         pub exp: [u8; 256], \
         pub log: [u8; 256] \
         }} \
         \
         pub static TABLES: Tables = "
    )
    .expect("Could not write the GF(256) table prelude");

    generate_tables(&mut file);
}

fn generate_protobuf_modules(out_dir: &Path) {
    let proto_base = out_dir.join("proto");
    let wrapped_dir = proto_base.join("wrapped");
    let dss_dir = proto_base.join("dss");

    fs::create_dir_all(&wrapped_dir).expect("Could not create wrapped protobuf output directory");
    fs::create_dir_all(&dss_dir).expect("Could not create dss protobuf output directory");

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(path_str(&proto_base))
        .input("protobuf/version.proto")
        .include("protobuf")
        .run()
        .expect("protobuf codegen (version) failed");

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(path_str(&wrapped_dir))
        .input("protobuf/wrapped/share.proto")
        .input("protobuf/wrapped/secret.proto")
        .include("protobuf")
        .run()
        .expect("protobuf codegen (wrapped) failed");

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(path_str(&dss_dir))
        .input("protobuf/dss/share.proto")
        .input("protobuf/dss/metadata.proto")
        .input("protobuf/dss/secret.proto")
        .include("protobuf")
        .run()
        .expect("protobuf codegen (dss) failed");
}

fn write_protobuf_module_descriptors(out_dir: &Path, manifest_dir: &Path) {
    let generated_proto_dir = out_dir.join("proto");
    let src_proto_dir = manifest_dir.join("src").join("proto");

    let proto_mod = format!(
        "#[cfg(feature = \"dss\")]\n#[path = {dss_mod}]\npub mod dss;\n\
         #[path = {version_rs}]\npub mod version;\n\
         #[path = {wrapped_mod}]\npub mod wrapped;\n",
        dss_mod = rust_path_literal(&src_proto_dir.join("dss").join("mod.rs")),
        version_rs = rust_path_literal(&generated_proto_dir.join("version.rs")),
        wrapped_mod = rust_path_literal(&src_proto_dir.join("wrapped").join("mod.rs")),
    );

    let wrapped_mod = format!(
        "#[path = {secret_rs}]\npub mod secret;\n\
         #[path = {share_rs}]\npub mod share;\n\
         pub use crate::proto::version;\n",
        secret_rs = rust_path_literal(&generated_proto_dir.join("wrapped").join("secret.rs")),
        share_rs = rust_path_literal(&generated_proto_dir.join("wrapped").join("share.rs")),
    );

    let dss_mod = format!(
        "#[path = {metadata_rs}]\npub mod metadata;\n\
         #[path = {secret_rs}]\npub mod secret;\n\
         #[path = {share_rs}]\npub mod share;\n\
         pub use crate::proto::version;\n",
        metadata_rs = rust_path_literal(&generated_proto_dir.join("dss").join("metadata.rs")),
        secret_rs = rust_path_literal(&generated_proto_dir.join("dss").join("secret.rs")),
        share_rs = rust_path_literal(&generated_proto_dir.join("dss").join("share.rs")),
    );

    fs::write(out_dir.join("proto_mod.rs"), proto_mod)
        .expect("Could not write root protobuf module descriptor");
    fs::write(out_dir.join("proto_wrapped_mod.rs"), wrapped_mod)
        .expect("Could not write wrapped protobuf module descriptor");
    fs::write(out_dir.join("proto_dss_mod.rs"), dss_mod)
        .expect("Could not write dss protobuf module descriptor");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for proto in PROTO_FILES {
        println!("cargo:rerun-if-changed={proto}");
    }

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is not set");
    let out_dir = Path::new(&out_dir);
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is not set");
    let manifest_dir = Path::new(&manifest_dir);

    generate_gf256_tables(out_dir);
    generate_protobuf_modules(out_dir);
    write_protobuf_module_descriptors(out_dir, manifest_dir);
}
