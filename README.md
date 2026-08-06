> [!WARNING]  
> This is very much a work in progress.  Do not depend on the output remaining stable in the short term.
>

# security-data-collider

Takes the fragments of various security data source snapshots to build a control dataset that we enrich on top of.  Git will let
us know when there are conflicts which need resolved between our data and upstream.

We can then create a single unified view per Anchore security identifier by combining the fragments from the enrichment dataset with the
upstream records.
