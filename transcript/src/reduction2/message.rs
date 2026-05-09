use crate::reduction2::NoError;
use std::{any::Any, fmt::Debug};

/// Any message must consist of a constant number of field elements,
/// or a number which is function of some paramenters.
pub trait Message<F>: Any + Clone + Debug {
    /// The information needed to determine the length of the message.
    /// Use () if it is a constant.
    type Params;
    // Possible error when converting element into field elements.
    type Error: Debug;

    /// The message length should be defined by the type and parameters
    /// for all possible valid values.
    /// You may ignore invalid values here as you can output an error
    /// when handling them.
    fn len(params: &Self::Params) -> usize;
    /// This should never panic, if the value is invalid it should
    /// return an error.
    /// Ideally, the type will be designed such that all possible values
    /// are valid. But that isn't always possible, and for such cases,
    /// errors should be used.
    /// Avoid using the expected_len to "fix" the length of message, use
    /// it only to check the result if the type is not enough and output
    /// an error.
    fn to_field_elements(&self, expected_len: usize) -> Result<Vec<F>, Self::Error>;
}

/// Used internally to handle generating challenge points.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PointRound;

impl<F> Message<F> for PointRound {
    type Params = ();

    type Error = NoError;

    fn len(_params: &()) -> usize {
        0
    }

    fn to_field_elements(&self, _params: usize) -> Result<Vec<F>, Self::Error> {
        Ok(vec![])
    }
}
