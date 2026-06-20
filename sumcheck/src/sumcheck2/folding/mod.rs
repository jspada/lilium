use crate::folding::utils::FieldFolder;

mod reduction;
mod zerofold;

pub use reduction::SumFold;
pub use zerofold::ZeroFold;

trait Foldable<F> {
    fn fold(folder: &FieldFolder<F>, a: Self, b: Self) -> Self;
}
