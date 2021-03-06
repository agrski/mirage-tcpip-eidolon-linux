(*
 * Copyright (c) 2010 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

(** TCP segments *)

val info : Log.t
val debug : Log.t

(** The receive queue stores out-of-order segments, and can coalesece
    them on input and pass on an ordered list up the stack to the
    application.

    It also looks for control messages and dispatches them to
    the Rtx queue to ack messages or close channels.
*)
module Rx (T:V1_LWT.TIME) : sig

  type segment
  (** Individual received TCP segment *)

  val pp_segment: Format.formatter -> segment -> unit

  val segment:
    sequence:Sequence.t -> fin:bool -> syn:bool -> rst:bool -> ack:bool ->
    ack_number:Sequence.t -> window:int -> data:Cstruct.t ->
    segment

  type t
  (** Queue of receive segments *)

  val pp: Format.formatter -> t -> unit

  val create:
    rx_data:(Cstruct.t list option * int option) Lwt_mvar.t ->
    wnd:Window.t ->
    state:State.t ->
    tx_ack:(Sequence.t * int) Lwt_mvar.t ->
    t

  val is_empty : t -> bool

  val input : t -> segment -> unit Lwt.t
  (** Given an input segment, the window information, and a receive
      queue, update the window, extract any ready segments into the
      user receive queue, and signal any acks to the Tx queue *)

end

type tx_flags = No_flags | Syn | Fin | Rst | Psh | SynFin
(** Either Syn/Fin/Rst allowed, but not combinations *)

(** Pre-transmission queue *)
module Tx (Time:V1_LWT.TIME)(Clock:V1.CLOCK) : sig

  type xmit = flags:tx_flags -> wnd:Window.t -> options:Options.t list ->
    seq:Sequence.t -> ecn:bool -> Cstruct.t list -> unit Lwt.t

  type t
  (** Queue of pre-transmission segments *)

  val create:
    xmit:xmit -> wnd:Window.t -> state:State.t ->
    rx_ack:Sequence.t Lwt_mvar.t ->
    tx_ack:(Sequence.t * int) Lwt_mvar.t ->
    tx_wnd_update:int Lwt_mvar.t -> t * unit Lwt.t

  val output:
    ?flags:tx_flags -> ?options:Options.t list -> ?ecn:bool -> t -> Cstruct.t list ->
    unit Lwt.t
  (** Queue a segment for transmission. May block if:

      {ul
        {- There is no transmit window available.}
        {- The wire transmit function blocks.}}

      The transmitter should check that the segment size will will not
      be greater than the transmit window.  *)

end
