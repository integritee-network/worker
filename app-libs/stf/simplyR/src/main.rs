use clap::{Parser, ValueEnum};
use simplyr_lib::{
    custom_fair_matching, pay_as_bid_matching, GridFeeMatrix, GridFeeMatrixRaw, MarketInput,
};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Algorithm {
    PayAsBid,
    CustomFair,
}

/// Command line arguments
#[derive(Parser, Clone, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Which matching algorithm to run
    #[arg(short, long, value_name = "NAME")]
    algo: Algorithm,

    /// Sets a the JSON file that includes the orders
    #[arg(short, long, value_name = "FILE.json")]
    orders: PathBuf,

    /// Sets a the JSON file that includes the grid fee matrix (only used in custom fair matching)
    #[arg(short, long, value_name = "FILE.json")]
    grid_fee_matrix: Option<PathBuf>,

    /// Sets the energy unit (in kWh) that is used to divide Orders in our custom fair matching
    #[arg(short, long, value_name = "NUM")]
    energy_unit: Option<f64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.algo {
        Algorithm::PayAsBid => {
            let file = File::open(&args.orders)?;
            let reader = BufReader::new(file);
            let market_input: MarketInput = serde_json::from_reader(reader)?;
            {
                let market_output = pay_as_bid_matching(&market_input);
                let mut stdout = std::io::stdout();
                serde_json::to_writer_pretty(&mut stdout, &market_output)?;
            }
        }
        Algorithm::CustomFair => {
            let market_input: MarketInput = {
                let file = File::open(&args.orders)?;
                let reader = BufReader::new(file);
                serde_json::from_reader(reader)?
            };

            let grid_fee_matrix: GridFeeMatrix = {
                let file = File::open(args.grid_fee_matrix.unwrap())?;
                let reader = BufReader::new(file);
                let raw: GridFeeMatrixRaw = serde_json::from_reader(reader)?;
                GridFeeMatrix::from_raw(&raw)?
            };

            {
                let market_output = custom_fair_matching(
                    &market_input,
                    args.energy_unit.unwrap_or(1.0),
                    &grid_fee_matrix,
                );
                let mut stdout = std::io::stdout();
                serde_json::to_writer_pretty(&mut stdout, &market_output)?;
            }
        }
    }

    Ok(())
}
