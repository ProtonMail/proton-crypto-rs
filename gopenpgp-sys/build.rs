use bindgen::EnumVariation;
use std::env;
use std::fs::OpenOptions;
use std::io::{stderr, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

const GO_LIB_NAME: &str = "gopenpgp-sys";

#[cfg(any(target_os = "linux", target_os = "android"))]
const GO_LIB_SUFFIX: &str = "a";

#[cfg(target_os = "macos")]
const GO_LIB_SUFFIX: &str = "a";

#[cfg(target_os = "windows")]
const GO_LIB_SUFFIX: &str = "dll";

#[cfg(target_os = "macos")]
const MIN_MAC_OS_X_VERSION: &str = "11.0";

const MIN_IOS_VERSION: &str = "15";

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum CPUArch {
    X86_64,
    X86,
    Aarch64,
    Arm,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum IosTarget {
    Simulator,
    SimulatorArm,
    Device,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum Platform {
    Unix(CPUArch),
    Windows(CPUArch),
    Android(CPUArch),
    Ios(IosTarget),
}

impl Platform {
    fn from_env() -> Self {
        let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
        let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let target = env::var("TARGET").unwrap();

        match (os.as_str(), arch.as_str()) {
            ("android", "x86_64") => Self::Android(CPUArch::X86_64),
            ("android", "aarch64") => Self::Android(CPUArch::Aarch64),
            ("android", "arm") => Self::Android(CPUArch::Arm),
            ("android", "x86") => Self::Android(CPUArch::X86),
            ("ios", "x86_64") => Self::Ios(IosTarget::Simulator),
            ("ios", "aarch64" | "arm64") if target.is_sim() => Self::Ios(IosTarget::SimulatorArm),
            ("ios", "aarch64" | "arm64") => Self::Ios(IosTarget::Device),
            ("windows", "x86_64") => Self::Windows(CPUArch::X86_64),
            ("windows", "x86") => Self::Windows(CPUArch::X86),
            ("macos" | "linux", "x86_64") => Self::Unix(CPUArch::X86_64),
            ("macos" | "linux", "aarch64" | "arm64") => Self::Unix(CPUArch::Aarch64),
            (os, arch) => panic!("unsupported architecture: {os}/{arch}"),
        }
    }
}

#[derive(Debug, Default, Clone)]
struct BindingEnvironmentArguments {
    lib_clang_path: Option<String>,
    clang_args: Vec<String>,
}

impl BindingEnvironmentArguments {
    fn apply(&self, bindgen_builder: bindgen::Builder) -> bindgen::Builder {
        if let Some(lib_clang_path) = &self.lib_clang_path {
            env::set_var("LIBCLANG_PATH", lib_clang_path);
        }

        let mut builder = bindgen_builder;
        for clang_arg in &self.clang_args {
            builder = builder.clang_arg(clang_arg);
        }
        builder
    }
}

fn main() {
    let platform = Platform::from_env();
    let (lib_dir, lib_path) = target_path_for_go_lib(platform);

    println!("cargo:rustc-link-search={}", lib_dir.to_str().unwrap());
    println!("cargo:rustc-link-lib={GO_LIB_NAME}");
    println!("cargo:rerun-if-changed=go");

    let bindings_env = build_go_lib(&lib_path, &lib_dir, platform);
    generate_bindings_go_for_lib(&lib_dir, &bindings_env);

    std::fs::copy(
        &lib_path,
        lib_dir
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .expect("Failed to navigate to the correct parent directory")
            .join(lib_path.file_name().unwrap()),
    )
    .expect("Failed to copy gpa to build dir");
}

fn target_path_for_go_lib(platform: Platform) -> (PathBuf, PathBuf) {
    let lib_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is not empty"));
    match platform {
        Platform::Unix(_) | Platform::Windows(_) => (
            lib_dir.clone(),
            lib_dir.join(format!("lib{GO_LIB_NAME}.{GO_LIB_SUFFIX}")),
        ),
        Platform::Android(_) => (
            lib_dir.clone(),
            lib_dir.join(format!("lib{GO_LIB_NAME}.so")),
        ),
        Platform::Ios(_) => (lib_dir.clone(), lib_dir.join(format!("lib{GO_LIB_NAME}.a"))),
    }
}

fn build_go_lib(
    lib_path: &Path,
    lib_dir: &Path,
    platform: Platform,
) -> BindingEnvironmentArguments {
    let mut command = Command::new("go");
    command
        .current_dir("go")
        .env("CGO_ENABLED", "1")
        .arg("build")
        .arg("-trimpath");

    let binding_env = match platform {
        Platform::Unix(arch) => prepare_go_lib_build_unix(&mut command, arch),
        Platform::Windows(arch) => prepare_go_lib_build_windows(&mut command, arch),
        Platform::Android(arch) => prepare_go_lib_build_android(&mut command, arch),
        Platform::Ios(target) => prepare_go_lib_build_ios(&mut command, target),
    };
    command.arg("-o").arg(lib_path);

    let output = command
        .output()
        .expect("Failed to get go build command output");
    if !output.status.success() {
        eprintln!("{command:?}");
        eprint!("Failed to compile go library:");
        stderr()
            .write_all(output.stderr.as_slice())
            .expect("Error write failed");
        panic!("Go lib build failed");
    }

    if let Platform::Windows(_) = platform {
        post_process_go_lib_build_windows(lib_dir);
    }
    binding_env
}

fn generate_bindings_go_for_lib(lib_dir: &Path, binding_args: &BindingEnvironmentArguments) {
    let header = lib_dir.join("libgopenpgp-sys.h");

    let generated_bindings =
        PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR should be set")).join("gopenpgp-sys.rs");

    let mut bindings_builder = bindgen::Builder::default();
    bindings_builder = binding_args.apply(bindings_builder);
    let bindings = bindings_builder
        .header(header.to_str().unwrap())
        .derive_debug(false)
        .impl_debug(false)
        .clang_arg("-I./go")
        .blocklist_item("__USE.*")
        .blocklist_item("_POSIX.*")
        .blocklist_item("__G.*")
        .blocklist_item("__STDC.*")
        .blocklist_item("__HAVE.*")
        .blocklist_item("__S.*")
        .blocklist_item("__glib.*")
        .layout_tests(false)
        .default_enum_style(EnumVariation::Rust {
            non_exhaustive: false,
        })
        .generate()
        .expect("Unable to generate go lib bindings");

    bindings
        .write_to_file(generated_bindings)
        .expect("Failed to write bindings to file");
}

fn prepare_go_lib_build_android(
    command: &mut Command,
    arch: CPUArch,
) -> BindingEnvironmentArguments {
    // Extract the correct location of the clang compiler from cargo ndk variables this is required so that
    // go compiles correctly. cargo ndk helps, but the CC environment variable points to a generic clang
    // binary which is later customized with target modifiers. Go will only work if you use the target
    // specific compiler.
    command.env("GOOS", "android");

    let platform = env::var("CARGO_NDK_ANDROID_PLATFORM").unwrap_or_else(|_| {
        // Print a warning if the environment variable is not set
        eprintln!("Warning: CARGO_NDK_ANDROID_PLATFORM is not set, will use default 30");
        30.to_string() // default use ndk api level 30.
    });

    let ndk_home = env::var("ANDROID_NDK_HOME")
        .or_else(|_| env::var("NDK_HOME"))
        .or_else(|_| env::var("ANDROID_NDK"))
        .expect(
            "None of the environment variables (ANDROID_NDK_HOME, NDK_HOME, ANDROID_NDK) are set",
        );

    // Determine the prebuilt directory based on the host OS
    let host_os = if cfg!(target_os = "windows") {
        "windows-x86_64"
    } else if cfg!(target_os = "macos") {
        "darwin-x86_64"
    } else {
        "linux-x86_64"
    };

    let (goarch, ndk_toolchain_prefix) = match arch {
        CPUArch::X86_64 => ("amd64", "x86_64-linux-android"),
        CPUArch::X86 => ("386", "i686-linux-android"),
        CPUArch::Aarch64 => ("arm64", "aarch64-linux-android"),
        CPUArch::Arm => ("arm", "armv7a-linux-androideabi"),
    };

    // Set environment variable for GOARCH
    command.env("GOARCH", goarch);

    // Special case: set environment variable for GOARM
    if let CPUArch::Arm = arch {
        command.env("GOARM", "7");
    }

    let ndk_toolchain = PathBuf::from(ndk_home)
        .join("toolchains")
        .join("llvm")
        .join("prebuilt")
        .join(host_os);

    // Set the appropriate CC environment variable
    let cc = ndk_toolchain
        .clone()
        .join("bin")
        .join(format!("{ndk_toolchain_prefix}{platform}-clang"))
        .to_str()
        .expect("valid path to CC")
        .to_string();
    command.env("CC", cc).arg("-buildmode=c-shared");

    // Set sysroot for bindings
    let sys_root = ndk_toolchain
        .join("sysroot")
        .to_str()
        .expect("valid sysroot ndk path")
        .to_owned();
    let sys_root_arg = format!("--sysroot={sys_root}");
    BindingEnvironmentArguments {
        lib_clang_path: None,
        clang_args: vec![sys_root_arg],
    }
}

fn prepare_go_lib_build_ios(
    command: &mut Command,
    target: IosTarget,
) -> BindingEnvironmentArguments {
    command.env("GOOS", "ios");

    let (clang_path, sdk_path) = (get_ios_clang_path(target), get_ios_sdk_path(target));
    let mut cflags = match target {
        IosTarget::Simulator => {
            command.env("GOARCH", "amd64");
            command.env("SDK", "iphonesimulator");
            format!("-mios-simulator-version-min={MIN_IOS_VERSION} -arch x86_64")
        }
        IosTarget::SimulatorArm => {
            command.env("GOARCH", "arm64");
            command.env("SDK", "iphonesimulator");
            format!("-mios-simulator-version-min={MIN_IOS_VERSION} -arch arm64")
        }
        IosTarget::Device => {
            command.env("GOARCH", "arm64");
            command.env("SDK", "iphoneos");
            format!("-miphoneos-version-min={MIN_IOS_VERSION} -arch arm64")
        }
    };
    cflags = format!("{cflags} -fembed-bitcode -isysroot {sdk_path}");

    command
        .env("CC", clang_path.clone())
        .env("CGO_CFLAGS", cflags.clone())
        .env("CGO_LDFLAGS", cflags)
        .arg("-buildmode=c-archive");

    let lib_clang_path = PathBuf::from(clang_path)
        .ancestors()
        .nth(2)
        .expect("Failed to find `lib` directory for libclang")
        .join("lib")
        .to_str()
        .expect("Failed to convert libclang path to string")
        .to_string();

    let sys_root_arg = format!("--sysroot={sdk_path}");
    BindingEnvironmentArguments {
        lib_clang_path: Some(lib_clang_path),
        clang_args: vec![sys_root_arg],
    }
}

fn prepare_go_lib_build_windows(
    command: &mut Command,
    arch: CPUArch,
) -> BindingEnvironmentArguments {
    // On windows clang must be available for bindgen, if not in path set LIBCLANG_PATH"
    // On windows mingw must be available for cgo, if not in path set MINGW_PATH"
    command.env("GOOS", "windows");
    match arch {
        CPUArch::X86_64 => command.env("GOARCH", "amd64"),
        CPUArch::X86 => command.env("GOARCH", "386"),
        CPUArch::Aarch64 => panic!("not supported for windows: Aarch64"),
        CPUArch::Arm => panic!("not supported for windows: Arm"),
    };
    // Check that a compatible compiler is available.
    if let Ok(mingw_path) = env::var("MINGW_PATH") {
        command.env("PATH", mingw_path);
    } else {
        Command::new("gcc")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .expect("On windows mingw must be available for cgo, if not in path set MINGW_PATH (gcc not found)");
        Command::new("gendef")
            .arg("-h")
            .output()
            .map(|output| output.status.success())
            .expect("On windows mingw must be available for cgo, if not in path set MINGW_PATH (gendef not found)");
        Command::new("dlltool")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .expect("On windows mingw must be available for cgo, if not in path set MINGW_PATH (dlltool not found)");
    }
    // For now windows needs to be compiled as dll since go can only compile on
    // windows with mingw. By default, rust uses the MSVC toolchain on windows
    // for greater compatability. To avoid runtime CRT runtime collisions the go library
    // needs to remain isolated from the other processes.
    command.arg("-buildmode=c-shared");
    BindingEnvironmentArguments::default()
}

fn prepare_go_lib_build_unix(command: &mut Command, arch: CPUArch) -> BindingEnvironmentArguments {
    #[cfg(target_os = "macos")]
    command.env("GOOS", "darwin");

    if arch == CPUArch::Aarch64 {
        command.env("GOARCH", "arm64");
    } else if arch == CPUArch::X86_64 {
        command.env("GOARCH", "amd64");
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    add_linux_compile_flags(command);

    #[cfg(target_os = "macos")]
    add_mac_os_compile_flags(command);

    command.arg("-buildmode=c-archive");
    BindingEnvironmentArguments::default()
}

fn post_process_go_lib_build_windows(lib_dir: &Path) {
    generate_win_lib_from_dll(lib_dir);
    patch_header_file(lib_dir);
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn add_linux_compile_flags(command: &mut Command) {
    //command.arg("-ldflags");
    //#command.arg(format!("-extldflags -Wl,-soname,lib{GO_LIB_NAME}.so"));
    command.arg("-gccgoflags");
    command.arg("-fPIC");
}

#[cfg(target_os = "macos")]
fn add_mac_os_compile_flags(command: &mut Command) {
    command
        .arg("-gccgoflags")
        .arg(format!("-mmacosx-version-min={MIN_MAC_OS_X_VERSION}"))
        .arg("-ldflags");
    #[allow(clippy::suspicious_command_arg_space)]
    command.arg(format!(
        "-extldflags -mmacosx-version-min={MIN_MAC_OS_X_VERSION}"
    ));
}

fn generate_win_lib_from_dll(lib_dir: &Path) {
    // Generate def file
    let mut command = Command::new("gendef");
    if let Ok(mingw_path) = env::var("MINGW_PATH") {
        command.env("PATH", mingw_path);
    }
    let output = command
        .current_dir(lib_dir.to_str().expect("Failed to extract lib_dir"))
        .arg(format!("lib{GO_LIB_NAME}.{GO_LIB_SUFFIX}"))
        .output()
        .expect("Failed to run the gendef command");
    if !output.status.success() {
        eprint!("Failed to generate def file for go library dll:");
        stderr()
            .write_all(output.stderr.as_slice())
            .expect("Error write failed");
        panic!("Go lib transformation failed");
    }

    // Transform dll
    let mut command = Command::new("dlltool");
    if let Ok(mingw_path) = env::var("MINGW_PATH") {
        command.env("PATH", mingw_path);
    }
    let output = command
        .current_dir(lib_dir.to_str().expect("Failed to extract lib_dir"))
        .arg("-d")
        .arg(format!("lib{GO_LIB_NAME}.def"))
        .arg("-l")
        .arg(format!("{GO_LIB_NAME}.lib"))
        .output()
        .expect("Failed to run the dlltool command");
    if !output.status.success() {
        eprint!("Failed to generate lib file for go library dll:");
        stderr()
            .write_all(output.stderr.as_slice())
            .expect("Error write failed");
        panic!("Go lib transformation failed");
    }
}

/// Patches the produced cgo header file to not include complex numbers.
///
/// The patch is necessary for compatibility with MSVC C++17 and other versions.
/// Complex numbers are not touched by the crypto library so removing them should not cause any issues.
/// If this should become a problem, we could investigate if there is a more fine-grained patch that works
/// for all MSVC versions.
fn patch_header_file(lib_dir: &Path) {
    const EXISTING: &str = "#ifdef _MSC_VER
#include <complex.h>
typedef _Fcomplex GoComplex64;
typedef _Dcomplex GoComplex128;
#else
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;
#endif";
    const PATCH: &str = "";

    let header_file_name = format!("lib{GO_LIB_NAME}.h");
    let mut header =
        std::fs::read_to_string(lib_dir.join(&header_file_name)).expect("No header file found");
    header = header.replace(EXISTING, PATCH);
    let mut new_header_file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(lib_dir.join(&header_file_name))
        .expect("Failed to open header file");
    new_header_file
        .write_all(header.as_bytes())
        .expect("Failed to write patched header file");
    new_header_file.flush().unwrap();
}

fn get_ios_sdk_path(target: IosTarget) -> String {
    let mut command = Command::new("xcrun");
    command.arg("--sdk");
    if target == IosTarget::Device {
        command.arg("iphoneos");
    } else {
        command.arg("iphonesimulator");
    }
    command.arg("--show-sdk-path");

    let output = command.output().expect("failed to get iOS SDK path");
    if !output.status.success() {
        stderr()
            .write_all(output.stderr.as_slice())
            .expect("Error write failed");
        panic!("xcrun did not succeed");
    }

    String::from_utf8(output.stdout).unwrap().replace('\n', "")
}

fn get_ios_clang_path(target: IosTarget) -> String {
    let mut command = Command::new("xcrun");
    command.arg("--sdk");
    if target == IosTarget::Device {
        command.arg("iphoneos");
    } else {
        command.arg("iphonesimulator");
    }
    command.arg("--find").arg("clang");

    let output = command.output().expect("failed to get iOS Clang path");
    if !output.status.success() {
        stderr()
            .write_all(output.stderr.as_slice())
            .expect("Error write failed");
        panic!("xcrun did not succeed");
    }

    String::from_utf8(output.stdout).unwrap().replace('\n', "")
}

trait TargetExt {
    fn is_sim(&self) -> bool;
}

impl<T: AsRef<str>> TargetExt for T {
    fn is_sim(&self) -> bool {
        self.as_ref().ends_with("-sim")
    }
}
