use std::env;
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::num::Wrapping;
use std::path::Path;

const POLY: u8 = 0x1D;

/// replicates the least significant bit to every other bit
#[inline]
fn mask(bit: u8) -> u8 {
    (Wrapping(0u8) - Wrapping(bit & 1)).0
}

/// multiplies a polynomial with x and returns the residual
/// of the polynomial division with POLY as divisor
#[inline]
fn xtimes(poly: u8) -> u8 {
    (poly << 1) ^ (mask(poly >> 7) & POLY)
}

struct Tables {
    exp: [u8; 256],
    log: [u8; 256],
}

fn generate_tables(mut file: &File) {
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

    match write!(file, "{}", tabs) {
        Ok(()) => {}
        Err(_) => panic!("Could not format the table. Aborting build."),
    };
}

fn farray(array: [u8; 256], f: &mut fmt::Formatter) -> fmt::Result {
    for (index, value) in array.into_iter().enumerate() {
        write!(f, "{}", value)?;
        if index != array.len() - 1 {
            write!(f, ",")?;
        }
    }
    Ok(())
}

impl fmt::Display for Tables {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

#[allow(unused_must_use)]
fn main() {
    // Generate GF(256) lookup tables
    let out_dir = env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("nothinghardcoded.rs");

    let mut f = File::create(&dest).unwrap();

    write!(
        f,
        "pub struct Tables {{ \
         pub exp: [u8; 256], \
         pub log: [u8; 256] \
         }} \
         \
         pub static TABLES: Tables = "
    );

    generate_tables(&f);

    // Generate protobuf code — separate calls per package to avoid name collisions
    let proto_base = Path::new("src/proto");

    // version.proto (no package)
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(proto_base.to_str().unwrap())
        .input("protobuf/version.proto")
        .include("protobuf")
        .run()
        .expect("protobuf codegen (version) failed");

    // wrapped package — also include version.proto since wrapped/secret.proto imports it
    let wrapped_dir = proto_base.join("wrapped");
    std::fs::create_dir_all(&wrapped_dir).unwrap();
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(wrapped_dir.to_str().unwrap())
        .input("protobuf/wrapped/share.proto")
        .input("protobuf/wrapped/secret.proto")
        .include("protobuf")
        .run()
        .expect("protobuf codegen (wrapped) failed");

    // Fix: wrapped/secret.rs references super::version, but version is at proto level.
    // Add re-export in wrapped/mod.rs
    {
        let wrapped_mod = wrapped_dir.join("mod.rs");
        let mut wf = File::create(&wrapped_mod).unwrap();
        write!(
            wf,
            "#![allow(missing_docs)]\n\
             pub mod secret;\n\
             pub mod share;\n\
             pub use crate::proto::version;\n"
        );
    }

    // dss package
    let dss_dir = proto_base.join("dss");
    std::fs::create_dir_all(&dss_dir).unwrap();
    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(dss_dir.to_str().unwrap())
        .input("protobuf/dss/share.proto")
        .input("protobuf/dss/metadata.proto")
        .input("protobuf/dss/secret.proto")
        .include("protobuf")
        .run()
        .expect("protobuf codegen (dss) failed");

    // Fix: dss/secret.rs references super::version, but version is at proto level.
    // Also re-export metadata for sibling access.
    {
        let dss_mod = dss_dir.join("mod.rs");
        let mut df = File::create(&dss_mod).unwrap();
        write!(
            df,
            "#![allow(missing_docs)]\n\
             pub mod metadata;\n\
             pub mod secret;\n\
             pub mod share;\n\
             pub use crate::proto::version;\n"
        );
    }

    // Write hand-crafted mod.rs that codegen can't generate
    // (codegen only knows about version.proto at the top level)
    let mod_rs = proto_base.join("mod.rs");
    let mut mod_file = File::create(&mod_rs).unwrap();
    write!(
        mod_file,
        "#![allow(missing_docs, unused_qualifications)]\n\
         #[cfg(feature = \"dss\")]\n\
         pub mod dss;\n\
         pub mod version;\n\
         pub mod wrapped;\n"
    );
}
