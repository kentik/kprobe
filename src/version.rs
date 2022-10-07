#[derive(Clone, Debug)]
pub struct Version {
    pub name:    String,
    pub version: String,
    pub arch:    String,
    pub system:  String,
    pub commit:  String,
    pub detail:  String,
}

impl Version {
    pub fn new() -> Self {
        let version = version();
        let commit  = commit();
        let detail  = format!("{} ({})", version, commit);
        Self {
            name:    env!("CARGO_PKG_NAME").to_owned(),
            version: version,
            arch:    arch(),
            system:  system(),
            commit:  commit,
            detail:  detail,
        }

    }
}

fn version() -> String {
    match option_env!("BUILD_VERSION") {
        Some(version) => version,
        None          => env!("CARGO_PKG_VERSION"),
    }.to_owned()
}

fn commit() -> String {
    option_env!("BUILD_COMMIT").unwrap_or("<unknown>").to_owned()
}

fn arch() -> String {
    option_env!("BUILD_ARCH").unwrap_or("<unknown>").to_owned()
}

fn system() -> String {
    option_env!("BUILD_SYSTEM").unwrap_or("<unknown>").to_owned()
}
