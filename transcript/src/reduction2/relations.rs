/// A relation between a structure, an instance and a witness.
pub trait Relation {
    type Structure;
    type Instance;
    type Witness;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool;
}

/// The unit relation.
impl Relation for () {
    type Structure = ();

    type Instance = ();

    type Witness = ();

    fn check(structure: &(), instance: &(), witness: &()) -> bool {
        #[allow(clippy::match_single_binding)]
        match (structure, instance, witness) {
            ((), (), ()) => true,
        }
    }
}

/// The compound relation (R1,R2) is essentially R1, but
/// with the structures of both R1 and R2.
pub struct CompoundRelation<R1, R2>(R1, R2);

impl<R1: Relation, R2: Relation> Relation for CompoundRelation<R1, R2> {
    type Structure = (R1::Structure, R2::Structure);

    type Instance = R1::Instance;

    type Witness = R1::Witness;

    fn check(
        structure: &Self::Structure,
        instance: &Self::Instance,
        witness: &Self::Witness,
    ) -> bool {
        R1::check(&structure.0, instance, witness)
    }
}
