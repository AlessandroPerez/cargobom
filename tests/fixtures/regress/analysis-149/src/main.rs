// round 14: a selector read from the command line through clap's derive (jwt-cli's `--alg`):
// the call passing the parsed arguments carries no algorithm, and is followed for the input
use clap::{Args, Parser, Subcommand, ValueEnum};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use std::collections::HashMap;

#[derive(Clone, ValueEnum)]
enum Alg { Hs256, Hs384, Hs512 }

#[derive(Args)]
struct EncodeArgs {
    #[arg(long, value_enum)]
    alg: Alg,
}

#[derive(Subcommand)]
enum Commands { Encode(EncodeArgs) }

#[derive(Parser)]
struct App {
    #[command(subcommand)]
    command: Commands,
}

fn translate(a: &Alg) -> Algorithm {
    match a {
        Alg::Hs256 => Algorithm::HS256,
        Alg::Hs384 => Algorithm::HS384,
        Alg::Hs512 => Algorithm::HS512,
    }
}

fn encode_token(args: &EncodeArgs) -> String {
    let claims: HashMap<String, String> = HashMap::new();
    let key = EncodingKey::from_secret(b"placeholder");
    encode(&Header::new(translate(&args.alg)), &claims, &key).unwrap_or_default()
}

fn main() {
    let app = App::parse();
    match &app.command {
        Commands::Encode(args) => println!("{}", encode_token(args)),
    }
}
