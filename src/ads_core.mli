type proof = Ezjsonm.value list

module type AUTHENTIKIT = sig
  type 'a auth
  type 'a authenticated_computation

  val return : 'a -> 'a authenticated_computation
  val bind : 'a authenticated_computation
              -> ('a -> 'b authenticated_computation)
              -> 'b authenticated_computation

  val (>>=) : 'a authenticated_computation
              -> ('a -> 'b authenticated_computation)
              -> 'b authenticated_computation

  module Authenticatable : sig
    type 'a evidence

    val auth : 'a auth evidence
    val pair : 'a evidence -> 'b evidence -> ('a * 'b) evidence
    val sum : 'a evidence -> 'b evidence -> [`left of 'a | `right of 'b] evidence

    val string : string evidence
    val int : int evidence
  end

  val auth : 'a Authenticatable.evidence -> 'a -> 'a auth
  val unauth : 'a Authenticatable.evidence -> 'a auth -> 'a authenticated_computation
end

module Prover : sig
  include AUTHENTIKIT with type 'a authenticated_computation = proof * 'a
  val get_hash : 'a auth -> string
end

module Verifier : sig
  type 'a proof_result =
    | Ok of 'a
    | ProofFailure

  include AUTHENTIKIT
    with type 'a authenticated_computation = proof -> (proof * 'a) proof_result
     and type 'a auth = string
end
