type proof = Ezjsonm.value list

let hash_json : Ezjsonm.value -> string =
  let hash_algo = Cryptokit.Hash.sha1 () in
  fun value ->
    Cryptokit.hash_string hash_algo (Ezjsonm.to_string (`A [value]))

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
  include AUTHENTIKIT
    with type 'a authenticated_computation = proof * 'a

  val get_hash : 'a auth -> string
end = struct
  type 'a auth = 'a * string
  type 'a authenticated_computation = proof * 'a

  let get_hash = snd

  let return a = ([], a)

  let bind (proof, value) fn =
    let (proof', result) = fn value in
    (proof @ proof', result) 

  let (>>=) = bind

  module Authenticatable = struct
    type 'a evidence = ('a -> Ezjsonm.value)

    let auth (_, hash) = `String hash

    let pair a_serializer b_serializer (a, b) =
      `A [a_serializer a; b_serializer b]

    let sum a_serializer b_serializer = function
      | `left a -> `A [`String "left"; a_serializer a]
      | `right b -> `A [`String "right"; b_serializer b]

    let string s = `String s
    let int i = `String (string_of_int i)
  end

  let auth serializer a = (a, hash_json (serializer a))
  let unauth serializer (a, b) = ([serializer a], a)
end

module Verifier : sig
  type 'a proof_result =
    | Ok of 'a
    | ProofFailure

  include AUTHENTIKIT
    with type 'a authenticated_computation = proof -> (proof * 'a) proof_result
     and type 'a auth = string
end = struct
  type 'a proof_result =
    | Ok of 'a
    | ProofFailure

  type 'a auth = string
  type 'a authenticated_computation = proof -> (proof * 'a) proof_result

  let return a = fun proof -> Ok (proof, a)

  let bind computation fn =
    fun proofs ->
      match computation proofs with
      | Ok (proofs', a) -> fn a proofs'
      | ProofFailure -> ProofFailure

  let (>>=) = bind

  module Authenticatable = struct
    type 'a evidence =
      { serialize : 'a -> Ezjsonm.value
      ; deserialize : Ezjsonm.value -> 'a option
      }

    let auth =
      let serialize h = `String h
      and deserialize = function
        | `String s -> Some s
        | _ -> None
      in
      { serialize; deserialize }

    let pair a_evidence b_evidence =
      let serialize (a, b) = `A [a_evidence.serialize a; b_evidence.serialize b]
      and deserialize = function
        | `A [x; y] -> begin
            match a_evidence.deserialize x, b_evidence.deserialize y with
            | Some a, Some b -> Some (a, b)
            | _ -> None
          end

        | _ -> None
      in
      { serialize; deserialize }

    let sum a_evidence b_evidence =
      let serialize = function
        | `left a -> `A [`String "left"; a_evidence.serialize a]
        | `right b -> `A [`String "right"; b_evidence.serialize b]
      and deserialize = function
        | `A [`String "left"; x] -> begin
            match a_evidence.deserialize x with
            | Some a -> Some (`left a)
            | _ -> None
          end

        | `A [`String "right"; y] -> begin
            match b_evidence.deserialize y with
            | Some b -> Some (`right b)
            | _ -> None
          end

        | _ -> None
      in
      { serialize; deserialize }

    let string =
      let serialize s = `String s
      and deserialize = function
        | `String s -> Some s
        | _ -> None
      in
      { serialize; deserialize }

    let int =
      let serialize i = `String (string_of_int i)
      and deserialize = function
        | `String i -> begin
            try Some (int_of_string i)
            with Failure _ -> None
          end
        | _ -> None
      in
      { serialize; deserialize }
  end

  let auth auth_evidence a =
    let open Authenticatable in
    hash_json (auth_evidence.serialize a)

  let unauth auth_evidence hash proof =
    let open Authenticatable in
    match proof with
    | p::ps when hash_json p = hash -> begin
        match auth_evidence.deserialize p with
        | None -> ProofFailure
        | Some a -> Ok (ps, a)
      end
    | _ -> ProofFailure 
end
