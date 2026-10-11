---------------------- MODULE InformationFlowLatticeReaderDirectionBroken ----------------------
EXTENDS FiniteSets

CONSTANTS
    \* @type: Set(Int);
    Owners,
    \* @type: Set(Int);
    Principals,
    \* @type: Set(Int);
    Compartments

ASSUME Owners \subseteq Principals

\* @typeAlias: label = {tag: Str, owners: Set(Int), readers: Set(<<Int, Int>>), compartments: Set(Int)};
InformationFlowLattice_typedefs == TRUE

VARIABLES
    \* @type: $label;
    a,
    \* @type: $label;
    b,
    \* @type: $label;
    c

\* @type: <<$label, $label, $label>>;
vars == <<a, b, c>>

\* @type: $label;
Bottom ==
    [tag |-> "known", owners |-> {}, readers |-> {}, compartments |-> {}]

\* @type: $label;
Top ==
    [tag |-> "top", owners |-> {}, readers |-> {}, compartments |-> {}]

\* @type: $label => Bool;
IsKnown(label) ==
    label.tag = "known"

\* @type: ($label, Int) => Set(Int);
ReadersFor(label, owner) ==
    {reader \in Principals : <<owner, reader>> \in label.readers}

\* @type: $label => Bool;
ValidKnown(label) ==
    /\ IsKnown(label)
    /\ label.owners \subseteq Owners
    /\ label.readers \subseteq (label.owners \X Principals)
    /\ label.compartments \subseteq Compartments
    /\ \A owner \in label.owners : <<owner, owner>> \in label.readers

\* @type: $label => Bool;
ValidLabel(label) ==
    \/ label = Top
    \/ ValidKnown(label)

\* @type: ($label, $label) => Bool;
FlowsTo(source, destination) ==
    IF destination = Top
    THEN TRUE
    ELSE IF source = Top
    THEN FALSE
    ELSE
        /\ source.compartments \subseteq destination.compartments
        /\ source.owners \subseteq destination.owners
        /\ \A owner \in source.owners :
            ReadersFor(source, owner) \subseteq ReadersFor(destination, owner)

\* @type: ($label, $label) => $label;
JoinKnown(left, right) ==
    [tag |-> "known",
     owners |-> left.owners \cup right.owners,
     readers |->
        {pair \in Owners \X Principals :
            LET owner == pair[1] IN
                IF owner \in left.owners /\ owner \in right.owners
                THEN pair \in left.readers /\ pair \in right.readers
                ELSE pair \in left.readers \/ pair \in right.readers},
     compartments |-> left.compartments \cup right.compartments]

\* @type: ($label, $label) => $label;
Join(left, right) ==
    IF left = Top \/ right = Top
    THEN Top
    ELSE JoinKnown(left, right)

\* @type: ($label, $label) => Bool;
OperationalEgress(source, clearance) ==
    /\ source # Top
    /\ clearance # Top
    /\ FlowsTo(source, clearance)

\* @type: ($label, Int) => $label;
AddOwner(label, owner) ==
    [label EXCEPT
        !.owners = @ \cup {owner},
        !.readers = @ \cup ({owner} \X Principals)]

\* @type: ($label, Int, Int) => $label;
NarrowReader(label, owner, reader) ==
    [label EXCEPT !.readers = @ \ {<<owner, reader>>}]

\* @type: ($label, Int) => $label;
AddCompartment(label, compartment) ==
    [label EXCEPT !.compartments = @ \cup {compartment}]

Init ==
    /\ a = Bottom
    /\ b = Bottom
    /\ c = Bottom

\* @type: $label => Bool;
AdvanceA(next) ==
    /\ ValidLabel(next)
    /\ a' = next
    /\ UNCHANGED <<b, c>>

\* @type: $label => Bool;
AdvanceB(next) ==
    /\ ValidLabel(next)
    /\ b' = next
    /\ UNCHANGED <<a, c>>

\* @type: $label => Bool;
AdvanceC(next) ==
    /\ ValidLabel(next)
    /\ c' = next
    /\ UNCHANGED <<a, b>>

MutateA ==
    \/ \E owner \in Owners :
        /\ IsKnown(a)
        /\ owner \notin a.owners
        /\ AdvanceA(AddOwner(a, owner))
    \/ \E owner \in a.owners, reader \in Principals :
        /\ reader # owner
        /\ <<owner, reader>> \in a.readers
        /\ AdvanceA(NarrowReader(a, owner, reader))
    \/ \E compartment \in Compartments :
        /\ IsKnown(a)
        /\ compartment \notin a.compartments
        /\ AdvanceA(AddCompartment(a, compartment))
    \/ /\ a # Top
       /\ AdvanceA(Top)

MutateB ==
    \/ \E owner \in Owners :
        /\ IsKnown(b)
        /\ owner \notin b.owners
        /\ AdvanceB(AddOwner(b, owner))
    \/ \E owner \in b.owners, reader \in Principals :
        /\ reader # owner
        /\ <<owner, reader>> \in b.readers
        /\ AdvanceB(NarrowReader(b, owner, reader))
    \/ \E compartment \in Compartments :
        /\ IsKnown(b)
        /\ compartment \notin b.compartments
        /\ AdvanceB(AddCompartment(b, compartment))
    \/ /\ b # Top
       /\ AdvanceB(Top)

MutateC ==
    \/ \E owner \in Owners :
        /\ IsKnown(c)
        /\ owner \notin c.owners
        /\ AdvanceC(AddOwner(c, owner))
    \/ \E owner \in c.owners, reader \in Principals :
        /\ reader # owner
        /\ <<owner, reader>> \in c.readers
        /\ AdvanceC(NarrowReader(c, owner, reader))
    \/ \E compartment \in Compartments :
        /\ IsKnown(c)
        /\ compartment \notin c.compartments
        /\ AdvanceC(AddCompartment(c, compartment))
    \/ /\ c # Top
       /\ AdvanceC(Top)

Stutter ==
    UNCHANGED vars

Next ==
    \/ MutateA
    \/ MutateB
    \/ MutateC
    \/ Stutter

Spec ==
    /\ Init
    /\ [][Next]_vars

\* @type: Set($label);
CurrentLabels ==
    {a, b, c}

LabelsValid ==
    \A label \in CurrentLabels : ValidLabel(label)

Reflexive ==
    \A label \in CurrentLabels : FlowsTo(label, label)

Antisymmetric ==
    \A left \in CurrentLabels, right \in CurrentLabels :
        (FlowsTo(left, right) /\ FlowsTo(right, left)) => left = right

Transitive ==
    \A first \in CurrentLabels, second \in CurrentLabels, third \in CurrentLabels :
        (FlowsTo(first, second) /\ FlowsTo(second, third)) => FlowsTo(first, third)

JoinUpperBound ==
    \A left \in CurrentLabels, right \in CurrentLabels :
        /\ ValidLabel(Join(left, right))
        /\ FlowsTo(left, Join(left, right))
        /\ FlowsTo(right, Join(left, right))

JoinLeastUpperBound ==
    \A left \in CurrentLabels, right \in CurrentLabels, upper \in CurrentLabels :
        (FlowsTo(left, upper) /\ FlowsTo(right, upper)) => FlowsTo(Join(left, right), upper)

JoinAlgebra ==
    \A left \in CurrentLabels, right \in CurrentLabels, third \in CurrentLabels :
        /\ Join(left, right) = Join(right, left)
        /\ Join(left, left) = left
        /\ Join(Join(left, right), third) = Join(left, Join(right, third))

TopEgressDenied ==
    \A label \in CurrentLabels :
        /\ ~OperationalEgress(Top, label)
        /\ ~OperationalEgress(label, Top)

InformationFlowLattice ==
    /\ LabelsValid
    /\ Reflexive
    /\ Antisymmetric
    /\ Transitive
    /\ JoinUpperBound
    /\ JoinLeastUpperBound
    /\ JoinAlgebra
    /\ TopEgressDenied

SafetyInv ==
    InformationFlowLattice

=============================================================================
